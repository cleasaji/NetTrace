"""
Same beaconing signature as elsewhere in this portfolio (near-constant
interval connections to one destination), applied here to flows parsed
from a PCAP/flow export rather than live-captured events.
"""

import statistics
import uuid
from typing import List

from app.models import FlowRecord, ThreatFinding

MIN_CONNECTIONS = 5
MAX_COEFFICIENT_OF_VARIATION = 0.15


def detect_beaconing(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings = []
    by_pair = {}
    for f in sorted(flows, key=lambda x: x.timestamp):
        if f.protocol == "dns":
            continue
        by_pair.setdefault((f.src_ip, f.dst_ip), []).append(f)

    for (src_ip, dst_ip), conns in by_pair.items():
        if len(conns) < MIN_CONNECTIONS:
            continue
        timestamps = [c.timestamp for c in conns]
        intervals = [(b - a).total_seconds() for a, b in zip(timestamps, timestamps[1:])]
        if not intervals or statistics.mean(intervals) == 0:
            continue
        mean_interval = statistics.mean(intervals)
        cov = statistics.pstdev(intervals) / mean_interval

        if cov <= MAX_COEFFICIENT_OF_VARIATION:
            findings.append(ThreatFinding(
                finding_id=str(uuid.uuid4()), finding_type="c2_beaconing", severity="critical",
                source_ip=src_ip,
                description=f"{src_ip} -> {dst_ip}: {len(conns)} connections at ~{mean_interval:.0f}s "
                            f"intervals (CoV={cov:.3f}) -- possible C2 beaconing",
                evidence=[f"{c.timestamp.isoformat()} {c.src_ip} -> {c.dst_ip}:{c.dst_port}" for c in conns],
                score_contribution=40,
            ))

    return findings
