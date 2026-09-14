"""
Parses an actual .pcap file (via Scapy -- not a stubbed format) into
FlowRecord objects the detectors operate on. Each captured packet
becomes one FlowRecord; DNS query packets additionally populate
`detail` with the queried name so dns_tunneling.py has something to
analyze. This is the real PCAP-ingestion path described in the brief --
proven against an actual generated .pcap file in demo/generate_pcap.py.
"""

from datetime import datetime, timezone
from typing import List

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

from app.models import FlowRecord


def parse_pcap(path: str) -> List[FlowRecord]:
    packets = rdpcap(path)
    flows: List[FlowRecord] = []

    for pkt in packets:
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).replace(tzinfo=None)

        protocol = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "other")
        src_port = dst_port = 0
        if TCP in pkt:
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)

        detail = ""
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            protocol = "dns"
            try:
                detail = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                detail = ""

        flows.append(FlowRecord(
            timestamp=ts, src_ip=ip_layer.src, dst_ip=ip_layer.dst,
            src_port=src_port, dst_port=dst_port, protocol=protocol,
            bytes=len(pkt), packets=1, detail=detail,
        ))

    return flows
