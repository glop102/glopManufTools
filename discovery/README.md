# Discovery Service

A standalone broker process that manages scanner subprocesses and serves cached discovery results to clients over a Unix socket.

## Architecture

### Management Socket

The discovery server binds a Unix socket. Two categories of connection are expected:

- **Clients** — query cached data, subscribe to events, control scanners
- **Scanners** — register their capabilities, report results, receive start/stop commands

All messages are JSON framed with a 4-byte big-endian length header.

### Scanners

Each scanner type is its own process. Scanners connect to the management socket and register themselves, declaring what options they accept and which interfaces they are available on.

When asked to begin scanning, a scanner can self-re-exec under `pkexec` to acquire the privileges it needs. The socket path is passed as a CLI argument (`--socket-path`) so the elevated process can reconnect and re-register. The server should treat a re-registering scanner as a continuation, not a conflict.

Built-in scanners (e.g. mDNS, LLDP) are auto-started by the discovery server on launch but follow the same registration path as any external scanner.

### Privilege Model

No part of the discovery server itself runs as root. Each scanner is responsible for its own privilege lifecycle. When elevation is needed, the scanner re-execs itself under `pkexec`. This scopes privilege prompts to the specific scanner type rather than granting a blanket root elevation to the whole discovery process.

## Client API

```python
from discovery import DiscoveryClient

dsc = DiscoveryClient.connect()  # spawns server if not running

dsc.single_scan("mdns", domains=["_http._tcp.local"])
dsc.subscribe("mdns", domains=["_http._tcp.local"], callback=update_gui)
dsc.start_scanner("mdns", interfaces=["eth0"])
dsc.stop_scanner("mdns", interfaces=["eth0"])
dsc.get_active_interfaces()   # -> dict[scanner_name, list[str]]
dsc.get_inactive_interfaces()
```

Scanner types are strings, not an enum. Scanners self-register their available options and interfaces at connect time.

## Client Commands

- `single_scan` — start a scan and wait for results, then stop
- `subscribe` / `unsubscribe` — receive ongoing events of a given type
- `start_scanner` / `stop_scanner` — control per-interface scanner state
- `flush_cache` — clear all cached data and notify clients that all hardware has gone offline
- `no_exit_on_empty` — one-shot flag; server will exit when the last client disconnects unless a client clears this flag
