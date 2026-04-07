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

Built-in scanners (`mdns.v1`, `test`) can be launched on demand via the `start_builtin_scanner` command. External scanners can connect independently using the same protocol.

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

Listens on the IPv6 mDNS multicast address (`ff02::fb`, port 5353) using a dual-stack socket. Interface membership is managed dynamically: when the server sends `set_active_interfaces`, the scanner joins or leaves the multicast group on each named interface.

Parameters: `port` (default 5353), `bind_address` (default `::`)

Result types are defined in `discovery.scanners.mdns`:
- `MDNSHostData` — a host with its addresses and services
- `MDNSServiceData` — a single service instance (name, type, port, TXT records)
