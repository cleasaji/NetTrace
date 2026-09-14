import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models import FlowRecord
from app.detectors.port_scan import detect_port_scan
from app.detectors.beaconing import detect_beaconing
from app.detectors.brute_force import detect_brute_force
from app.detectors.suspicious_outbound import detect_suspicious_outbound
from app.detectors.dns_tunneling import detect_dns_tunneling

BASE = datetime(2026, 9, 1, 10, 0, 0)


def test_port_scan_vertical_detected():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=i), src_ip="10.0.0.66", dst_ip="10.0.0.10",
                   src_port=40000 + i, dst_port=20 + i, protocol="tcp", bytes=60)
        for i in range(20)
    ]
    findings = detect_port_scan(flows)
    assert any(f.finding_type == "port_scan_vertical" for f in findings)


def test_port_scan_not_flagged_for_few_ports():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=i), src_ip="10.0.0.66", dst_ip="10.0.0.10",
                   src_port=40000 + i, dst_port=20 + i, protocol="tcp", bytes=60)
        for i in range(3)
    ]
    assert detect_port_scan(flows) == []


def test_beaconing_detected_on_regular_interval():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=60 * i), src_ip="10.0.0.50",
                   dst_ip="203.0.113.77", dst_port=443, protocol="tcp", bytes=300)
        for i in range(6)
    ]
    findings = detect_beaconing(flows)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_brute_force_detected_on_repeated_short_auth_attempts():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=10 * i), src_ip="198.51.100.5",
                   dst_ip="10.0.0.20", dst_port=22, protocol="tcp", bytes=200)
        for i in range(9)
    ]
    findings = detect_brute_force(flows)
    assert len(findings) == 1
    assert findings[0].finding_type == "brute_force"


def test_brute_force_not_flagged_for_large_flows():
    # Same volume of connections, but each moves real session-sized data --
    # shouldn't look like repeated failed auth attempts.
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=10 * i), src_ip="198.51.100.5",
                   dst_ip="10.0.0.20", dst_port=22, protocol="tcp", bytes=500_000)
        for i in range(9)
    ]
    assert detect_brute_force(flows) == []


def test_suspicious_outbound_flags_large_external_transfer():
    flows = [FlowRecord(timestamp=BASE, src_ip="10.0.0.15", dst_ip="93.184.216.34",
                        dst_port=8443, protocol="tcp", bytes=80_000_000)]
    findings = detect_suspicious_outbound(flows)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_suspicious_outbound_ignores_private_destinations():
    flows = [FlowRecord(timestamp=BASE, src_ip="10.0.0.15", dst_ip="10.0.0.99",
                        dst_port=445, protocol="tcp", bytes=200_000_000)]
    assert detect_suspicious_outbound(flows) == []


def test_dns_tunneling_flags_long_high_entropy_queries():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=5 * i), src_ip="10.0.0.77", dst_ip="8.8.8.8",
                   protocol="dns", detail="kx7qz2p9mw3lts6vbn8j1r5hy0adfe4c.exfil.example.com")
        for i in range(5)
    ]
    findings = detect_dns_tunneling(flows)
    assert len(findings) == 1
    assert findings[0].finding_type == "dns_tunneling"


def test_dns_tunneling_ignores_normal_short_queries():
    flows = [
        FlowRecord(timestamp=BASE + timedelta(seconds=5 * i), src_ip="10.0.0.5", dst_ip="8.8.8.8",
                   protocol="dns", detail="www.google.com")
        for i in range(10)
    ]
    assert detect_dns_tunneling(flows) == []
