import json
import socket
import sys
from discovery.scanners.base_scanner import BaseScanner


class MdnsScanner(BaseScanner):
    def start(self, args: list[str]):
        _ = self.parse_args(args)
        self.connect_to_server()
        if self.server == None:
            raise RuntimeError(
                "Scanner returned from connect_to_server() without a valid self.server instance"
            )
        # Announce to the server we are a scanner and give the list of parameters that we take
        interfaces = [name for _, name in socket.if_nameindex()]
        announce = {
            "command": "announce",
            "type": "scanner",
            "name": "mdns",
            "parameters": ["domains"],
            "interfaces": interfaces,
        }
        self.server.send_msg(json.dumps(announce))
        # TODO - check if the server connection closed and then exit


if __name__ == "__main__":
    scanner = MdnsScanner()
    scanner.start(sys.argv[1:])
