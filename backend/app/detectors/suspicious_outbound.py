"""
Flags an unusually large outbound transfer to a public (non-private) IP
on an uncommon port -- a rough proxy for data exfiltration. Private
ranges are excluded from consideration entirely so internal backup/sync
traffic between internal hosts doesn't get flagged.
"""

import ipaddress
import uuid
from typing import List

from app.models import FlowRecord, ThreatFinding

LARGE_TRANSFER_BYTES = 50_000_000   # 50MB in one flow
COMMON_PORTS = {80, 443}              # normal web traffic isn't itself suspicious


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def detect_suspicious_outbound(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings = []
    for f in flows:
        if f.protocol == "dns":
            continue
        if _is_private(f.dst_ip):
            continue
        if f.bytes < LARGE_TRANSFER_BYTES:
            continue

        severity = "critical" if f.dst_port not in COMMON_PORTS else "medium"
        findings.append(ThreatFinding(
            finding_id=str(uuid.uuid4()), finding_type="suspicious_outbound", severity=severity,
            source_ip=f.src_ip,
            description=f"{f.src_ip} sent {f.bytes / 1_000_000:.1f}MB to external host "
                        f"{f.dst_ip}:{f.dst_port} in a single flow",
            evidence=[f"{f.timestamp.isoformat()} {f.src_ip} -> {f.dst_ip}:{f.dst_port} "
                      f"({f.bytes} bytes, {f.packets} packets)"],
            score_contribution=25 if severity == "medium" else 40,
        ))

    return findings
