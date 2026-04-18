# Discovery Service

A broker process that manages scanner subprocesses and serves cached discovery results to clients over a socket.

## Architecture

### Transport

The discovery server binds either a Unix domain socket (default) or a TCP socket. The default Unix socket path is `$XDG_RUNTIME_DIR/discovery`, falling back to `/tmp/glopmanuf/discovery`.

All messages are JSON objects framed with a 4-byte big-endian length header. See `discovery_messages.md` for the full protocol reference.

### Connections

Two categories of connection are expected:

- **Clients** — query cached data and control scanners
- **Scanners** — register their capabilities, report results, receive commands

Both must send an `announce` message on connect before any other commands are accepted.

### Scanners

Each scanner type is its own process. Scanners connect to the server and register themselves, declaring their name, available interfaces, and accepted parameters. The server caches all scanner state and result data, and broadcasts changes to all connected clients.

Built-in scanners (`mdns.v1`, `lldp.v1`, `test`) can be launched on demand via the `start_builtin_scanner` command. External scanners can connect independently using the same protocol.

### Privilege Model

The discovery server itself never runs as root. When a scanner needs elevated privileges (e.g. to open raw sockets), it calls `reexec()` from `BaseScanner`, which re-execs the process under `sudo -A -E`. The `-A` flag uses a bundled tkinter GUI askpass helper so the password prompt appears as a dialog. The `-E` flag preserves the environment so library paths survive the exec. This scopes privilege prompts to the specific scanner rather than elevating the whole discovery process.

### Server Lifecycle

By default the server exits when the last client disconnects. Pass `--persistent` to keep it running.

## Connecting

```python
from discovery.client import DiscoveryClient

# Connects to the server, spawning it if it is not already running.
client = DiscoveryClient.connect()

# Send and receive raw protocol messages (see discovery_messages.md).
client.send_msg({"command": "get_registered_scanners"})
msgs = client.read_msgs()
```

`DiscoveryClient` inherits from `MsgSocket` and speaks the protocol directly. Connections can target a Unix socket or TCP:

```python
DiscoveryClient.connect(unix_socket_path=Path("/run/user/1000/discovery"))
DiscoveryClient.connect(tcp_socket=("127.0.0.1", 9100))
```

## Writing a Scanner

Subclass `BaseScanner` from `discovery.scanners.base_scanner`:

```python
class MyScanner(BaseScanner):
    def start(self, args: list[str]) -> None:
        # parse args, connect, announce, then run your scan loop
        ...

    def stop(self) -> None:
        self._keep_running = False
```

Key helpers on `BaseScanner`:
- `parse_connection_args(argv)` — strips `--unix-socket` / `--tcp-socket` from argv and configures the connection
- `connect_to_server()` — opens the connection (does not spawn)
- `wait_for_registration()` — blocks until the server accepts the `announce`
- `reexec()` — re-execs under sudo when elevation is needed

## Built-in Scanners

### mDNS (`mdns.v1`)

Listens on an IPv6 UDP socket for mDNS responses. Interface membership is managed dynamically: when the server sends `set_active_interfaces`, the scanner joins or leaves the multicast group on each named interface. The scanner also sends periodic PTR queries to the multicast group — one for the top-level meta-query domain and one per already-known service type — to solicit responses from devices that don't advertise spontaneously.

Parameters:
- `port` (default `5353`) — UDP port to listen on
- `bind_address` (default `::`) — IPv6 address to bind to
- `multicast_group` (default `ff02::fb`) — IPv6 multicast group to join and query
- `query_domain` (default `_services._dns-sd._udp.local.`) — top-level PTR query domain sent on each active query cycle
- `active_query_delay` (default `4.0`) — seconds between active query bursts

Cache key: `{interface}/{hostname}`

Result types are defined in `discovery.scanners.mdns`:
- `MDNSHostData` — a host with its addresses and services
- `MDNSServiceData` — a single service instance (name, type, port, TXT records)

### LLDP (`lldp.v1`)

Listens passively for LLDP frames on active interfaces using a single raw `AF_PACKET` socket. Requires `CAP_NET_RAW` (or root). The scanner connects and announces without elevation; when the first interface is activated it attempts to open the raw socket and calls `reexec()` if that fails with `PermissionError`.

Entries expire automatically based on the TTL value in each LLDP frame (`received_at + ttl < now`). A shutdown LLDPDU (TTL = 0) removes the entry immediately.

Cache key: `{interface}/{chassis_id}`

Result type is `LLDPNeighborData` from `discovery.scanners.lldp`:
- `interface` — interface the neighbor was seen on
- `chassis_id` — formatted chassis ID string
- `port_id` — formatted port ID string
- `ttl` — hold time in seconds from the TTL TLV
- `received_at` — `time.time()` when the entry was last refreshed
- `system_name`, `system_description`, `port_description` — optional TLV strings
- `capabilities` — list of enabled capability labels (e.g. `['router', 'bridge']`)
- `management_addresses` — list of formatted management address strings
