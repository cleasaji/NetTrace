"""
The NetTrace API: upload a real .pcap file (or POST flow records
directly), run detection, and pull per-source-IP investigation reports.
"""

import tempfile
from typing import List, Dict
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import FlowRecord, ThreatFinding, InvestigationReport
from app.store import store
from app.engine import run_all_detectors
from app.threat_score import build_investigation_reports
from app.pcap_ingest import parse_pcap

app = FastAPI(title="NetTrace", description="Network threat detection & investigation engine.", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.post("/ingest/pcap")
async def ingest_pcap(file: UploadFile = File(...)):
    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        tmp.write(contents)
        tmp.flush()
        flows = parse_pcap(tmp.name)
    store.flows.extend(flows)
    return {"parsed_packets": len(flows), "total_flows": len(store.flows)}


@app.post("/ingest/flows", status_code=201)
def ingest_flows(flows: List[FlowRecord]):
    store.flows.extend(flows)
    return {"ingested": len(flows), "total_flows": len(store.flows)}


@app.post("/detect/run", response_model=List[ThreatFinding])
def run_detection():
    findings = run_all_detectors(store.flows)
    store.findings = findings
    return findings


@app.get("/reports", response_model=Dict[str, InvestigationReport])
def get_reports():
    return build_investigation_reports(store.findings)


@app.get("/reports/{source_ip}", response_model=InvestigationReport)
def get_report(source_ip: str):
    reports = build_investigation_reports(store.findings)
    if source_ip not in reports:
        raise HTTPException(status_code=404, detail="no findings for this source IP")
    return reports[source_ip]


@app.post("/reset")
def reset_store():
    store.clear()
    return {"status": "cleared"}


@app.get("/health")
def health():
    return {"status": "ok"}
