def _parse_tcp_socket(value: str) -> tuple[str, int]:
    """Parse HOST:PORT, handling IPv6 bracketed addresses like [::1]:1234."""
    if value.startswith("["):
        bracket_end = value.index("]")
        host = value[1:bracket_end]
        port = int(value[bracket_end + 2:])
    else:
        host, _, port_str = value.rpartition(":")
        port = int(port_str)
    return host, port
