"""
Schemas for NetTrace: a FlowRecord is one network conversation (or one
DNS query, modeled as a flow with protocol="dns" and the query in
`detail`), a ThreatFinding is one detector's output, and an
InvestigationReport aggregates every finding for a source IP into a
single threat score with an explanation.
"""

from datetime import datetime
from typing import List
from pydantic import BaseModel


class FlowRecord(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"    # tcp, udp, dns
    bytes: int = 0
    packets: int = 1
    detail: str = ""           # e.g. the DNS query string, for protocol="dns" flows


class ThreatFinding(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    source_ip: str
    description: str
    evidence: List[str]
    score_contribution: int       # points this finding adds to the source IP's threat score


class InvestigationReport(BaseModel):
    source_ip: str
    threat_score: int              # 0-100
    risk_level: str                  # low, medium, high, critical
    findings: List[ThreatFinding]
    summary: str
