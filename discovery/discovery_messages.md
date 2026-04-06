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

"scan_results_update"
    fields: results: list[dict]
    Sent when one or more discovered items are new or have changed. Each entry in results
    has a "key" (str, scanner-defined unique identifier) and a "result" (dict, the
    serialized scanner-specific result model). Semantics are upsert — sending an existing
    key replaces the cached entry.

"scan_results_remove"
    fields: keys: list[str]
    Sent when one or more previously reported items are no longer present. keys is the
    list of scanner-defined identifiers to remove from the cache.


### Client -> Server

"announce"
    fields: type="client"
    Sent once on connect to identify the connection as a client.

"set_active_interfaces"
    fields: scanner, interfaces
    Request that the named scanner change its active interface set.

"clear_cache"
    fields: scanners
    Request that the server clear its result cache for the named scanners and forward the
    clear request to each scanner so it can repopulate.

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

"get_results"
    fields: scanner
    Request the full cached result set for the named scanner.

"get_result"
    fields: scanner, key
    Request a single cached result by its key from the named scanner.


### Server -> Scanner

"set_scanner_parameters"
    fields: parameters: list[dict]
    Forwarded from a client request after validation.

"stop_scanner"
    fields: (none)
    Forwarded from a client request after validation. Scanner should exit on receipt.

"clear_cache"
    fields: (none)
    Sent after the server has already cleared its own result cache and broadcast
    scan_results_remove to all clients. Scanner should clear its internal state and
    repopulate by sending scan_results_update.

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

"scan_results_update"
    fields: scanner, results: list[dict]
    Forwarded to all clients when a scanner reports new or updated results. Each entry has
    "key" (str) and "result" (dict). Clients should deserialize "result" using the
    scanner-specific result type (e.g. discovery.scanners.mdns.MDNSHostData).

"scan_results_remove"
    fields: scanner, keys: list[str]
    Forwarded to all clients when a scanner reports results are gone, or immediately when
    the server processes a clear_cache request (before the scanner repopulates).

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
                               active_interfaces: list[str], parameters: dict[str, Any])

"get_registered_scanner" (client) -> (server)
    Client names a specific scanner.

    -> "status: accepted" (server) -> (client)
        name: str
        available_interfaces: list[str]
        active_interfaces: list[str]
        parameters: dict[str, Any]

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
        parameters: dict[str, Any]

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.


### Discovery Results

"scan_results_update" (scanner) -> (server)
    Scanner reports one or more new or updated discovered items. Upsert semantics —
    an existing key is replaced.

    -> "status: accepted" (server) -> (scanner)
        (no extra fields)

    -> "scan_results_update" (server) -> (all clients)
        scanner: str
        results: list[dict]  (each entry has "key": str and "result": dict)

"scan_results_remove" (scanner) -> (server)
    Scanner reports that one or more previously reported items are no longer present.

    -> "status: accepted" (server) -> (scanner)
        (no extra fields)

    -> "scan_results_remove" (server) -> (all clients)
        scanner: str
        keys: list[str]

"get_results" (client) -> (server)
    Client requests the full cached result set for a named scanner.

    -> "status: accepted" (server) -> (client)
        results: list[dict]  (each entry has "key": str and "result": dict)

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found.

"get_result" (client) -> (server)
    Client requests a single cached result by key from a named scanner.

    -> "status: accepted" (server) -> (client)
        key: str
        result: dict

    -> "status: rejected" (server) -> (client)
        reason: str
        Named scanner was not found, or key does not exist in its cache.

Result types are scanner-specific pydantic models. Clients import the type from the scanner
module and call model_validate() on the "result" dict received from the server:

    from discovery.scanners.mdns import MDNSHostData
    host = MDNSHostData.model_validate(result_dict)


### Cache Control

"clear_cache" (client) -> (server)
    Client requests that the result cache for a set of named scanners be cleared.
    Server validates that every named scanner is currently registered.

    -> "status: accepted" (server) -> (client)
        (no extra fields)

    For each named scanner, in order:

    -> "scan_results_remove" (server) -> (all clients)
        scanner: str
        keys: list[str]  (all keys currently in the server's cache for that scanner)
        Server immediately fans out the full removal list and clears its own cache.
        Only sent if the cache was non-empty.

    -> "clear_cache" (server) -> (scanner)
        (no extra fields)
        Server forwards the clear to the scanner after its own cache is already empty.
        Scanner should clear its internal state and repopulate by sending
        scan_results_update, which will rebuild the server cache and fan out to clients.

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
