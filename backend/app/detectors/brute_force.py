"""
Brute force at the network layer: many short-lived connection attempts
to an authentication-relevant port (SSH, RDP, SMB) from one source to
one destination in a short window -- inferred from connection COUNT and
small per-flow byte size (a real auth handshake+reject is small; a real
session moves much more data), since NetTrace only has flow metadata,
not application-layer auth success/failure.
"""

import uuid
from collections import defaultdict
from datetime import timedelta
from typing import List

from app.models import FlowRecord, ThreatFinding

AUTH_PORTS = {22, 3389, 445, 21, 23}
WINDOW = timedelta(minutes=3)
ATTEMPT_THRESHOLD = 8
MAX_BYTES_PER_ATTEMPT = 4096   # short flows only -- a real session would move more data


def detect_brute_force(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings = []
    candidates = [f for f in flows if f.dst_port in AUTH_PORTS and f.bytes <= MAX_BYTES_PER_ATTEMPT]

    grouped = defaultdict(list)
    for f in sorted(candidates, key=lambda x: x.timestamp):
        grouped[(f.src_ip, f.dst_ip, f.dst_port)].append(f)

    for (src_ip, dst_ip, port), attempts in grouped.items():
        window = [a for a in attempts if a.timestamp - attempts[0].timestamp <= WINDOW]
        if len(window) >= ATTEMPT_THRESHOLD:
            findings.append(ThreatFinding(
                finding_id=str(uuid.uuid4()), finding_type="brute_force", severity="high",
                source_ip=src_ip,
                description=f"{src_ip} made {len(window)} short connection attempts to "
                            f"{dst_ip}:{port} within {WINDOW.total_seconds()/60:.0f} minutes",
                evidence=[f"{a.timestamp.isoformat()} {a.src_ip} -> {a.dst_ip}:{a.dst_port} ({a.bytes}B)"
                          for a in window][:10],
                score_contribution=35,
            ))

    return findings
