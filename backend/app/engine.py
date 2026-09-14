"""
Runs every registered flow-based detector and returns the combined
findings list -- the same "one function per detector, engine just calls
them all" pattern used elsewhere in this portfolio, so adding a new
detector never means touching this file's logic, just its call list.
"""

from typing import List

from app.models import FlowRecord, ThreatFinding
from app.detectors.port_scan import detect_port_scan
from app.detectors.beaconing import detect_beaconing
from app.detectors.brute_force import detect_brute_force
from app.detectors.suspicious_outbound import detect_suspicious_outbound
from app.detectors.dns_tunneling import detect_dns_tunneling


def run_all_detectors(flows: List[FlowRecord]) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    findings.extend(detect_port_scan(flows))
    findings.extend(detect_beaconing(flows))
    findings.extend(detect_brute_force(flows))
    findings.extend(detect_suspicious_outbound(flows))
    findings.extend(detect_dns_tunneling(flows))
    return findings
