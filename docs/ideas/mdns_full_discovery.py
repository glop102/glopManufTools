"""mDNS full-discovery scanner PoC.

Chains DNS-SD queries automatically on a single interface:
  1. PTR  _services._dns-sd._udp.local  -> service types  (meta-query)
     PTR  <service type>                -> service instance names
  2. SRV + TXT per instance             -> hostname, port, metadata
  3. AAAA + A per hostname              -> IP addresses

The result model reflects the actual DNS-SD structure:
  MDNSHostData owns addresses and a list of MDNSServiceData.
  Services are children of a host, not the other way around.

Raw DNS records are stored in response_records as MDNSResponseRecord
objects (PTR = shared, rest = unique per DNS-SD).

Uses plain UDP sockets; scapy for DNS encode/decode only.
No root required.
"""

import argparse
import select
import socket
import struct
import time
from typing import Optional

from pydantic import BaseModel, computed_field
from scapy.layers.dns import DNS, DNSQR, dnstypes

MDNS_ADDR6 = "ff02::fb"
MDNS_PORT = 5353

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33


class MDNSResponseRecord(BaseModel):
    interface: str
    src_ip: str
    rrname: str
    rtype: int
    rdata: str
    ttl: int
    received_at: float
    response_time: Optional[float] = None  # None if record arrived unsolicited

    @computed_field
    @property
    def type_name(self) -> str:
        return dnstypes.get(self.rtype, str(self.rtype))

    @computed_field
    @property
    def is_shared(self) -> bool:
        """PTR records are shared (multiple devices can answer for one service type)."""
        return self.rtype == TYPE_PTR


class MDNSServiceData(BaseModel):
    instance_name: str
    service_type: str
    port: Optional[int] = None
    txt: dict[str, str] = {}

    def __eq__(self, other) -> bool:
        if not isinstance(other, MDNSServiceData):
            return NotImplemented
        return self.instance_name == other.instance_name

    def __hash__(self) -> int:
        return hash(self.instance_name)


class MDNSHostData(BaseModel):
    interface: str
    hostname: str
    addresses: list[str] = []
    services: list[MDNSServiceData] = []

    def __eq__(self, other) -> bool:
        if not isinstance(other, MDNSHostData):
            return NotImplemented
        return self.interface == other.interface and self.hostname == other.hostname

    def __hash__(self) -> int:
        return hash((self.interface, self.hostname))


def _make_socket(iface: str) -> socket.socket:
    ifindex = socket.if_nametoindex(iface)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    group = socket.inet_pton(socket.AF_INET6, MDNS_ADDR6)
    sock.setsockopt(
        socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group + struct.pack("I", ifindex)
    )
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    sock.bind(("", MDNS_PORT))
    return sock


def _iter_rrs(dns_pkt: DNS):
    """Yield all resource records from answer and additional sections."""
    for attr, count_attr in (("an", "ancount"), ("ar", "arcount")):
        if not getattr(dns_pkt, count_attr, 0):
            continue
        section = getattr(dns_pkt, attr, None)
        if section is None:
            continue
        for rr in section:
            yield rr


def _decode(val) -> str:
    return val.decode() if isinstance(val, bytes) else str(val)


def scan(service: str, iface: str, timeout: int = 5) -> None:
    if not service.endswith("."):
        service += "."

    response_records: list[MDNSResponseRecord] = []
    hosts: dict[str, MDNSHostData] = {}        # hostname -> MDNSHostData
    services: dict[str, MDNSServiceData] = {}  # instance_name -> MDNSServiceData (for SRV/TXT lookup)

    queried_ptr: set[str] = set()
    queried_srv: set[str] = set()
    queried_addr: set[str] = set()
    query_times: dict[str, float] = {}

    def send_query(name: str, qtype: str) -> None:
        if name not in query_times:
            query_times[name] = time.time()
        ifindex = socket.if_nametoindex(iface)
        pkt = bytes(DNS(rd=0, qd=DNSQR(qname=name, qtype=qtype)))
        sock.sendto(pkt, (MDNS_ADDR6, MDNS_PORT, 0, ifindex))

    def rx(src_ip: str, rtype: str, msg: str) -> None:
        print(f"[{src_ip}][{rtype}] {msg}")

    with _make_socket(iface) as sock:
        send_query(service, "PTR")
        print(f"[*] PTR  {service}")

        deadline = time.monotonic() + timeout

        while (remaining := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select([sock], [], [], min(remaining, 0.5))
            if not ready:
                continue

            data, (src_ip, _, _, _) = sock.recvfrom(4096)
            now = time.time()
            dns = DNS(data)
            if dns.ancount == 0 and dns.arcount == 0:
                continue

            for rr in _iter_rrs(dns):
                rtype = getattr(rr, "type", None)
                rrname = _decode(rr.rrname)
                ttl = getattr(rr, "ttl", 0)
                response_time = (now - query_times[rrname]) if rrname in query_times else None

                if rtype == TYPE_PTR:
                    if rrname.endswith(".arpa."):
                        continue
                    rdata = _decode(rr.rdata)
                    response_records.append(MDNSResponseRecord(
                        interface=iface, src_ip=src_ip, rrname=rrname, rtype=rtype,
                        rdata=rdata, ttl=ttl, received_at=now, response_time=response_time,
                    ))
                    rx(src_ip, "PTR", f"{rrname} -> {rdata}")

                    first_label = rdata.lstrip(".").split(".")[0]
                    if first_label.startswith("_"):
                        if rdata not in queried_ptr:
                            queried_ptr.add(rdata)
                            send_query(rdata, "PTR")
                            print(f"[*] PTR  {rdata}")
                            deadline = max(deadline, time.monotonic() + 2)
                    else:
                        if rdata not in services:
                            services[rdata] = MDNSServiceData(
                                instance_name=rdata,
                                service_type=rrname,
                            )
                        if rdata not in queried_srv:
                            queried_srv.add(rdata)
                            send_query(rdata, "SRV")
                            send_query(rdata, "TXT")
                            print(f"[*] SRV+TXT  {rdata}")
                            deadline = max(deadline, time.monotonic() + 2)

                elif rtype == TYPE_SRV:
                    port = rr.port
                    target = _decode(rr.target)
                    response_records.append(MDNSResponseRecord(
                        interface=iface, src_ip=src_ip, rrname=rrname, rtype=rtype,
                        rdata=f"{target}:{port}", ttl=ttl, received_at=now, response_time=response_time,
                    ))
                    rx(src_ip, "SRV", f"{rrname} -> {target}:{port}")
                    svc = services.get(rrname)
                    if svc is not None:
                        svc.port = port
                        if target not in hosts:
                            hosts[target] = MDNSHostData(interface=iface, hostname=target)
                        host = hosts[target]
                        if svc not in host.services:
                            host.services.append(svc)
                        # Backfill addresses already seen for this hostname
                        for rec in response_records:
                            if rec.rtype in (TYPE_A, TYPE_AAAA) and rec.rrname == target and rec.rdata not in host.addresses:
                                host.addresses.append(rec.rdata)
                    if target and target not in queried_addr:
                        queried_addr.add(target)
                        send_query(target, "AAAA")
                        send_query(target, "A")
                        print(f"[*] AAAA+A  {target}")
                        deadline = max(deadline, time.monotonic() + 2)

                elif rtype == TYPE_TXT:
                    txt = {}
                    for entry in rr.rdata:
                        entry = entry.decode(errors="replace") if isinstance(entry, bytes) else entry
                        if "=" in entry:
                            k, _, v = entry.partition("=")
                            txt[k] = v
                        elif entry:
                            txt[entry] = ""
                    response_records.append(MDNSResponseRecord(
                        interface=iface, src_ip=src_ip, rrname=rrname, rtype=rtype,
                        rdata=str(txt), ttl=ttl, received_at=now, response_time=response_time,
                    ))
                    svc = services.get(rrname)
                    if svc is not None:
                        svc.txt.update(txt)
                    rx(src_ip, "TXT", f"{rrname} -> {txt}")

                elif rtype in (TYPE_A, TYPE_AAAA):
                    label = "AAAA" if rtype == TYPE_AAAA else "A"
                    addr = _decode(rr.rdata)
                    response_records.append(MDNSResponseRecord(
                        interface=iface, src_ip=src_ip, rrname=rrname, rtype=rtype,
                        rdata=addr, ttl=ttl, received_at=now, response_time=response_time,
                    ))
                    host = hosts.get(rrname)
                    if host is not None and addr not in host.addresses:
                        host.addresses.append(addr)
                    rx(src_ip, label, f"{rrname} -> {addr}")

    # --- All response records ---
    print(f"\n=== Response Records ({len(response_records)}) ===")
    print(f"  {'time':>8}  {'rt_ms':>7}  {'src_ip':<40}  {'type':<5}  {'ttl':>6}  {'rrname':<45}  rdata")
    for rec in response_records:
        rt = f"{rec.response_time*1000:7.1f}" if rec.response_time is not None else "    n/a"
        ts = time.strftime("%H:%M:%S", time.localtime(rec.received_at))
        shared = "S" if rec.is_shared else "U"
        print(f"  {ts}  {rt}  {rec.src_ip:<40}  {rec.type_name:<5}[{shared}]  {rec.ttl:>6}  {rec.rrname:<45}  {rec.rdata}")

    # --- Assembled hosts ---
    print(f"\n=== Hosts ({len(hosts)}) ===")
    if not hosts:
        print("  No hosts assembled.")
        return

    for host in hosts.values():
        print(f"\n  {host.hostname}  [{', '.join(host.addresses)}]")
        for svc in host.services:
            print(f"    {svc.instance_name}")
            print(f"      service_type  : {svc.service_type}")
            if svc.port is not None:
                print(f"      port          : {svc.port}")
            for k, v in svc.txt.items():
                print(f"      txt           : {k}={v}" if v else f"      txt           : {k}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="mDNS full-discovery PoC")
    parser.add_argument("service", help="Service type or _services._dns-sd._udp.local")
    parser.add_argument("--iface", required=True, help="Network interface, e.g. eth0")
    parser.add_argument(
        "--timeout", type=int, default=5, help="Base listen timeout in seconds (default: 5)"
    )
    args = parser.parse_args()
    scan(args.service, args.iface, args.timeout)
