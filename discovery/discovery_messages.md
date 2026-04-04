# Discovery Protocol Messages

## Message Reference

All messages are JSON objects sent over a length-prefixed stream socket (4-byte big-endian
length header followed by a UTF-8 encoded JSON body). Every message has a "command" field
identifying its type. Additional fields are command-specific and are listed under each entry.

The DiscoveryServer is the authority for all protocol state. It is the only entity that sends
"status" messages, and it will always respond to every received command with a status message.

Example — a scanner announcing itself:

    {
        "command": "announce",
        "type": "scanner",
        "name": "test",
        "interfaces": ["eth0", "wlan0"],
        "parameters": {"interval": 2.0}
    }

Example — server accepting that announce:

    {
        "command": "status",
        "status": "accepted",
        "server_api_version": 1
    }



### Scanner -> Server

"announce"
    fields: type="scanner", name, interfaces, parameters
    Sent once on connect to identify the scanner and report its capabilities.
    parameters is a dict of parameter names to their current values as set by cli
    arguments or defaults.

"available_interfaces_changed"
    fields: interfaces
    Sent when the set of interfaces the scanner can see has changed. The provided list
    replaces the previously reported available interface set.

"active_interfaces_changed"
    fields: interfaces
    Sent when the scanner's actively scanning interfaces have changed. The provided list
    is the complete current set of interfaces being scanned.

"parameters_changed"
    fields: parameters: list[dict]
    Sent when one or more parameter values have changed.


### Client -> Server

"announce"
    fields: type="client"
    Sent once on connect to identify the connection as a client.

"set_active_interfaces"
    fields: scanner, interfaces
    Request that the named scanner change its active interface set.

"clear_cache"
    fields: scanners
    Request that the server and the named scanners clear their discovery caches.

"set_scanner_parameters"
    fields: scanner, parameters: list[dict]
    Request that the named scanner update one or more of its parameter values.

"stop_scanner"
    fields: scanner
    Request that the named scanner exit.

"start_builtin_scanner"
    fields: scanner
    Request that the server launch one of its built-in scanners by name.

"get_builtin_scanners"
    fields: (none)
    Request the list of scanners the server knows how to start.

"get_registered_scanners"
    fields: (none)
    Request the full list of registered scanners with their interface and parameter data.

"get_registered_scanner"
    fields: scanner
    Request the full state of a single registered scanner.

"get_scanner_available_interfaces"
    fields: scanner
    Request the available interface list for the named scanner.

"get_scanner_active_interfaces"
    fields: scanner
    Request the active interface list for the named scanner.

"get_scanner_parameters"
    fields: scanner
    Request the current parameter values for the named scanner.


### Server -> Scanner

"set_scanner_parameters"
    fields: parameters: list[dict]
    Forwarded from a client request after validation.

"stop_scanner"
    fields: (none)
    Forwarded from a client request after validation. Scanner should exit on receipt.

"clear_cache"
    fields: (none)
    Forwarded from a client clear_cache request after validation. Scanner should clear
    its discovery cache.

"set_active_interfaces"
    fields: interfaces
    Forwarded from a client request after validation. Scanner should replace its
    active interface set with exactly this list.


### Server -> Client

"available_scanners_changed"
    fields: scanners
    Sent to all clients when the set of registered scanners changes. Contains the complete
    current list of scanner names.

"available_interfaces_changed"
    fields: scanner, interfaces
    Forwarded to all clients when a scanner reports its available interface set has changed.

"active_interfaces_changed"
    fields: scanner, interfaces
    Forwarded to all clients when a scanner reports its active interface set has changed.

"parameters_changed"
    fields: scanner, parameters: list[dict]
    Forwarded to all clients when a scanner reports its parameter values have changed.

"status"
    fields: status, [reason], [...]
    Response to a client command.

    status: "accepted"
        Command was valid and has been forwarded or applied.
        On announce acceptance, server_api_version is included. For client connections,
        the current list of registered scanner names is also included.

    status: "rejected"
        Command was invalid or could not be applied.
        reason: human-readable string describing why. Not intended for parsing.
        Additional fields may be present depending on the rejection but are not guaranteed.


---

## Flows

### Connection Setup

"announce" (scanner) -> (server)
    Scanner sends its name, available interface list, and accepted parameter keys.
    Scanner names must be unique — a second scanner announcing with an already-registered
    name is rejected and the connection remains unannounced.

    -> "status: rejected" (server) -> (scanner)
        reason: str
        A scanner with that name is already registered. Connection is not promoted.

    -> "status: accepted" (server) -> (scanner)
        server_api_version: int
        Server promotes connection to a named ScannerConnection and confirms registration.

    -> "available_scanners_changed" (server) -> (all clients)
        Server notifies all clients of the updated scanner list.

"announce" (client) -> (server)
    Client identifies itself.

    -> "status: accepted" (server) -> (client)
        server_api_version: int
        scanners: list[str]
        Server confirms registration.

(scanner disconnects)
    Server removes the scanner from its registered list.

    -> "available_scanners_changed" (server) -> (all clients)
        Server notifies all clients of the updated scanner list.


### Scanner State Changes

"available_interfaces_changed" (scanner) -> (server)
    Scanner reports its available interface set has changed.
    Server always responds accepted and updates its cached scanner state.

    -> "status: accepted" (server) -> (scanner)
        (no extra fields)

    -> "available_interfaces_changed" (server) -> (all clients)
        Server forwards the change to every connected client with the scanner name attached.


"parameters_changed" (scanner) -> (server)
    Scanner reports that one or more of its parameter values have changed.
    Server always responds accepted and updates its cached scanner state.

    -> "status: accepted" (server) -> (scanner)
        (no extra fields)

    -> "parameters_changed" (server) -> (all clients)
        scanner: str
        parameters: list[dict]


### Scanner Lifecycle

"start_builtin_scanner" (client) -> (server)
    Client names a built-in scanner to launch.
    Server validates that the name matches a known built-in scanner.

    -> "status: accepted" (server) -> (client)
        (no extra fields)
        Server launches the scanner process. When the scanner connects and announces
        itself, "available_scanners_changed" will be sent to all clients as normal.

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner is not a known built-in.



"stop_scanner" (client) -> (server)
    Client names a scanner to stop.
    Server validates that the named scanner is currently registered.

    -> "status: accepted" (server) -> (client)
        (no extra fields)
        Server has forwarded the command to the scanner.

        -> "stop_scanner" (server) -> (scanner)
            (no extra fields)
            Scanner should exit on receipt. Disconnect will trigger
            "available_scanners_changed" to all clients.

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.


### Scanner Parameter Control

"set_scanner_parameters" (client) -> (server)
    Client names a scanner and provides a list of parameter updates.
    Server validates that every parameter name in the list exists in the scanner's
    registered parameter set.

    -> "status: accepted" (server) -> (client)
        (no extra fields)
        Server has forwarded the command to the scanner.

        -> "set_scanner_parameters" (server) -> (scanner)
            parameters: list[dict]

    -> "status: rejected" (server) -> (client)
        reason: str
        parameters: list[str]  (the unrecognized parameter names)
        Scanner is not contacted.

"parameters_changed" (scanner) -> (server)
    Scanner reports that its parameter values have changed after applying the update.
    Server always responds accepted and updates its cached scanner state.

    -> "status: accepted" (server) -> (scanner)
        (no extra fields)

    -> "parameters_changed" (server) -> (all clients)
        scanner: str
        parameters: list[dict]


### Client Basic Queries

"get_builtin_scanners" (client) -> (server)

    -> "status: accepted" (server) -> (client)
        scanners: list[str]

"get_registered_scanners" (client) -> (server)

    -> "status: accepted" (server) -> (client)
        scanners: list[dict]  (each entry contains name: str, available_interfaces: list[str],
                               active_interfaces: list[str], parameters: dict[str, str])

"get_registered_scanner" (client) -> (server)
    Client names a specific scanner.

    -> "status: accepted" (server) -> (client)
        name: str
        available_interfaces: list[str]
        active_interfaces: list[str]
        parameters: dict[str, str]

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.

"get_scanner_available_interfaces" (client) -> (server)
    Client names a specific scanner.

    -> "status: accepted" (server) -> (client)
        interfaces: list[str]

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.

"get_scanner_active_interfaces" (client) -> (server)
    Client names a specific scanner.

    -> "status: accepted" (server) -> (client)
        interfaces: list[str]

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.

"get_scanner_parameters" (client) -> (server)
    Client names a specific scanner.

    -> "status: accepted" (server) -> (client)
        parameters: dict[str, str]

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.


### Cache Control

"clear_cache" (client) -> (server)
    Client requests that the server and a set of named scanners clear their discovery caches.
    Server validates that every named scanner is currently registered.

    -> "status: accepted" (server) -> (client)
        (no extra fields)
        Server clears its own cache and forwards the command to each named scanner.

        -> "clear_cache" (server) -> (each named scanner)
            (no extra fields)
            Fire-and-forget. The scanner clears its state and reports all previously
            discovered hosts as offline through the normal discovery reporting path,
            which is the mechanism that drives the actual cache clear.

    -> "status: rejected" (server) -> (client)
        reason: str
        scanners: list[str]  (the unrecognized scanner names)
        No scanners are contacted.


### Scanner Control

"set_active_interfaces" (client) -> (server)
    Client requests that a named scanner change its active interface set.
    Server validates that the named scanner exists and that every requested interface
    is present in that scanner's reported list.

    -> "status: accepted" (server) -> (client)
        (no extra fields)
        All requested interfaces were valid. Server has forwarded the command to the scanner.

    -> "status: rejected" (server) -> (client)
        reason: str
        interfaces: list[str]  (the unrecognized interface names, if that was the cause)
        Named scanner was not found, or one or more interface names were not in the
        scanner's reported interface list. reason field describes which.
        Scanner is not contacted.

    [accepted path] "set_active_interfaces" (server) -> (scanner)
        Server forwards the validated interface list. Scanner may ignore this entirely,
        including if its active interface list already matches. Flow ends there if so.

    -> "active_interfaces_changed" (scanner) -> (server)
        Scanner reports the interfaces it is now actively scanning after applying the change.
        Server always responds accepted and updates its cached scanner state.

        -> "status: accepted" (server) -> (scanner)
            (no extra fields)

        -> "active_interfaces_changed" (server) -> (all clients)
            Server forwards the change to every connected client, adding the scanner name
            so clients can attribute the change.
