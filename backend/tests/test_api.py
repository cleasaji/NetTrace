import os
import sys
import subprocess
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from app.main import app
from app.store import store

client = TestClient(app)
BASE = datetime(2026, 9, 1, 10, 0, 0)


def setup_function():
    store.clear()


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_ingest_flows_and_run_detection_end_to_end():
    flows = [
        {"timestamp": (BASE + timedelta(seconds=60 * i)).isoformat(), "src_ip": "10.0.0.50",
         "dst_ip": "203.0.113.77", "dst_port": 443, "protocol": "tcp", "bytes": 300}
        for i in range(6)
    ]
    resp = client.post("/ingest/flows", json=flows)
    assert resp.status_code == 201

    detect_resp = client.post("/detect/run")
    findings = detect_resp.json()
    assert any(f["finding_type"] == "c2_beaconing" for f in findings)


def test_reports_endpoint_returns_scored_report():
    flows = [
        {"timestamp": (BASE + timedelta(seconds=60 * i)).isoformat(), "src_ip": "10.0.0.50",
         "dst_ip": "203.0.113.77", "dst_port": 443, "protocol": "tcp", "bytes": 300}
        for i in range(6)
    ]
    client.post("/ingest/flows", json=flows)
    client.post("/detect/run")

    resp = client.get("/reports")
    reports = resp.json()
    assert "10.0.0.50" in reports
    assert reports["10.0.0.50"]["threat_score"] > 0
    assert reports["10.0.0.50"]["risk_level"] in ("low", "medium", "high", "critical")


def test_report_404_for_ip_with_no_findings():
    resp = client.get("/reports/1.2.3.4")
    assert resp.status_code == 404


def test_pcap_ingestion_via_upload_parses_real_pcap():
    pcap_path = os.path.join(os.path.dirname(__file__), "..", "demo", "attack_scenario.pcap")
    if not os.path.exists(pcap_path):
        subprocess.run(
            ["python3", os.path.join(os.path.dirname(__file__), "..", "demo", "generate_pcap.py")],
            check=True,
        )

    with open(pcap_path, "rb") as f:
        resp = client.post("/ingest/pcap", files={"file": ("attack_scenario.pcap", f, "application/octet-stream")})
    assert resp.status_code == 200
    assert resp.json()["parsed_packets"] > 0

    detect_resp = client.post("/detect/run")
    findings = detect_resp.json()
    finding_types = {f["finding_type"] for f in findings}
    # the generated pcap scripts a port scan, beaconing, and DNS tunneling
    assert "port_scan_vertical" in finding_types
    assert "c2_beaconing" in finding_types
    assert "dns_tunneling" in finding_types


def test_reset_clears_store():
    client.post("/ingest/flows", json=[{
        "timestamp": BASE.isoformat(), "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
        "dst_port": 80, "protocol": "tcp", "bytes": 100,
    }])
    client.post("/reset")
    resp = client.get("/reports")
    assert resp.json() == {}
