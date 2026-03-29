import os
import sys
from discovery.scanners.base_scanner import BaseScanner

class MdnsScanner(BaseScanner):
    def start(self, args: list[str]):
        print(args)
        _ = self.parse_args(args)
        if os.getuid() != 0:
            self.reexec()
        self.connect_to_server()
        # TODO - add an announce method to the base scanner that tells the server we are a scanner and gives the list of parameters that we take
        # TODO - check if the server connection closed and then exit

if __name__ == "__main__":
    scanner = MdnsScanner()
    scanner.start(sys.argv[1:])