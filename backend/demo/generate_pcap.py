"""
Builds an actual .pcap file with Scapy containing a port scan, C2
beaconing, and DNS-tunneling-style queries -- proving the ingestion
path parses real packet captures, not synthetic JSON standing in for one.

Run: python demo/generate_pcap.py
Then: curl -F "file=@demo/attack_scenario.pcap" http://localhost:8000/ingest/pcap
"""

import os
import random
import string
from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

OUT_PATH = os.path.join(os.path.dirname(__file__), "attack_scenario.pcap")


def random_label(n=40):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def main():
    packets = []
    base_time = 1_757_750_400.0  # arbitrary fixed epoch time for reproducibility

    # Port scan: 10.0.0.66 probes 20 ports on 10.0.0.10 in quick succession.
    for i, port in enumerate(range(20, 40)):
        pkt = IP(src="10.0.0.66", dst="10.0.0.10") / TCP(sport=40000 + i, dport=port, flags="S")
        pkt.time = base_time + i * 0.2
        packets.append(pkt)

    # C2 beaconing: 10.0.0.50 connects to 203.0.113.77:443 every 60 seconds, 6 times.
    for i in range(6):
        pkt = IP(src="10.0.0.50", dst="203.0.113.77") / TCP(sport=50000, dport=443, flags="S")
        pkt.time = base_time + 500 + i * 60
        packets.append(pkt)

    # DNS tunneling: 10.0.0.77 issues long, random (high-entropy) subdomain queries.
    for i in range(5):
        query = random_label(45) + ".exfil.example.com"
        pkt = (
            IP(src="10.0.0.77", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=query))
        )
        pkt.time = base_time + 1000 + i * 5
        packets.append(pkt)

    wrpcap(OUT_PATH, packets)
    print(f"Wrote {len(packets)} packets to {OUT_PATH}")


if __name__ == "__main__":
    main()
