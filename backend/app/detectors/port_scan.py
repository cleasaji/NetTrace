"""
Port scan detection: one source IP contacting an unusually large number
of distinct destination ports (vertical scan against one host) or
distinct destination hosts (horizontal scan) within a short window --
the two classic scan shapes, detected separately so the evidence names
which shape actually occurred.
"""

import uuid
from datetime import timedelta
from typing import List

from app.models import FlowRecord, ThreatFinding

WINDOW = timedelta(minutes=2)
VERTICAL_SCAN_PORT_THRESHOLD = 15    # distinct ports on one dst_ip
HORIZONTAL_SCAN_HOST_THRESHOLD = 10    # distinct dst_ips on the same port


def detect_port_scan(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings = []
    by_src = {}
    for f in sorted(flows, key=lambda x: x.timestamp):
        by_src.setdefault(f.src_ip, []).append(f)

    for src_ip, src_flows in by_src.items():
        window = [f for f in src_flows if f.timestamp - src_flows[0].timestamp <= WINDOW]

        by_dst_ip = {}
        for f in window:
            by_dst_ip.setdefault(f.dst_ip, set()).add(f.dst_port)

        for dst_ip, ports in by_dst_ip.items():
            if len(ports) >= VERTICAL_SCAN_PORT_THRESHOLD:
                findings.append(ThreatFinding(
                    finding_id=str(uuid.uuid4()), finding_type="port_scan_vertical",
                    severity="high", source_ip=src_ip,
                    description=f"{src_ip} probed {len(ports)} distinct ports on {dst_ip} "
                                f"within {WINDOW.total_seconds()/60:.0f} minutes",
                    evidence=[f"{f.timestamp.isoformat()} {f.src_ip} -> {f.dst_ip}:{f.dst_port}"
                              for f in window if f.dst_ip == dst_ip][:10],
                    score_contribution=30,
                ))

        dst_ips_by_port = {}
        for f in window:
            dst_ips_by_port.setdefault(f.dst_port, set()).add(f.dst_ip)
        for port, hosts in dst_ips_by_port.items():
            if len(hosts) >= HORIZONTAL_SCAN_HOST_THRESHOLD:
                findings.append(ThreatFinding(
                    finding_id=str(uuid.uuid4()), finding_type="port_scan_horizontal",
                    severity="high", source_ip=src_ip,
                    description=f"{src_ip} probed port {port} across {len(hosts)} distinct hosts "
                                f"within {WINDOW.total_seconds()/60:.0f} minutes",
                    evidence=[f"{f.timestamp.isoformat()} {f.src_ip} -> {f.dst_ip}:{f.dst_port}"
                              for f in window if f.dst_port == port][:10],
                    score_contribution=30,
                ))

    return findings
