"""
DNS tunneling detection from flow-level DNS queries: tunneling encodes
payload data into subdomain labels, which makes queries both unusually
LONG and unusually high-ENTROPY (encoded/compressed data looks close to
random compared to human-chosen hostnames) -- both signals together,
since a long-but-low-entropy query (a long real hostname) or a
short-but-high-entropy one (a short random subdomain, not uncommon) are
each individually weaker evidence.
"""

import math
import uuid
from collections import Counter, defaultdict
from typing import List

from app.models import FlowRecord, ThreatFinding

LENGTH_THRESHOLD = 50       # characters in the query name
ENTROPY_THRESHOLD = 3.5      # bits per character (English text is typically ~3.0-3.5)
MIN_SUSPICIOUS_QUERIES_FOR_VOLUME_FLAG = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_dns_tunneling(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings = []
    dns_flows = [f for f in flows if f.protocol == "dns" and f.detail]

    suspicious_by_src = defaultdict(list)
    for f in dns_flows:
        query = f.detail
        if len(query) >= LENGTH_THRESHOLD and _shannon_entropy(query) >= ENTROPY_THRESHOLD:
            suspicious_by_src[f.src_ip].append(f)

    for src_ip, suspicious_flows in suspicious_by_src.items():
        if len(suspicious_flows) >= 3:  # a handful is enough to report, volume flag adds severity
            severity = "critical" if len(suspicious_flows) >= MIN_SUSPICIOUS_QUERIES_FOR_VOLUME_FLAG else "high"
            findings.append(ThreatFinding(
                finding_id=str(uuid.uuid4()), finding_type="dns_tunneling", severity=severity,
                source_ip=src_ip,
                description=f"{src_ip} issued {len(suspicious_flows)} long, high-entropy DNS queries "
                            f"consistent with DNS tunneling",
                evidence=[f"{f.timestamp.isoformat()} query={f.detail[:60]}... "
                          f"(len={len(f.detail)}, entropy={_shannon_entropy(f.detail):.2f})"
                          for f in suspicious_flows[:10]],
                score_contribution=35 if severity == "high" else 45,
            ))

    return findings
