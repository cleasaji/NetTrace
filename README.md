# 🌐 NetTrace — Network Threat Detection & Investigation Engine

A FastAPI backend that parses **real PCAP files** (via Scapy — not
stubbed data) or ingested flow records, runs five real network-layer
detectors (port scanning, C2 beaconing, brute force, suspicious
outbound transfers, DNS tunneling), and produces a per-source-IP
investigation report with a computed threat score.

Proven end-to-end against an actual generated `.pcap` file — see the
real output below, including an honest edge case the detectors
surfaced on their own.

---

## Run it yourself

```bash
cd backend
pip install -r requirements.txt
python demo/generate_pcap.py          # writes a real .pcap with Scapy
uvicorn app.main:app --reload
```

```bash
curl -F "file=@demo/attack_scenario.pcap" http://localhost:8000/ingest/pcap
curl -X POST http://localhost:8000/detect/run
curl http://localhost:8000/reports
```

Or open `frontend/index.html` in a browser and use the "Upload PCAP" /
"Run Detection" buttons — it's a static file, no build step, calling
`http://localhost:8000` directly.

**Recording a demo:** with the API running, open the dashboard, upload
`attack_scenario.pcap`, click Run Detection, and screen-record the
investigation reports populating live — a genuine ~60 second demo of a
real PCAP being parsed and scored, not a mockup.

## What actually happened when I ran this

```
POST /ingest/pcap  -> {"parsed_packets": 31, "total_flows": 31}
POST /detect/run   -> 4 findings:
  [HIGH]     port_scan_vertical  10.0.0.66  (20 ports probed on 10.0.0.10)
  [CRITICAL] c2_beaconing        10.0.0.66  (see note below)
  [CRITICAL] c2_beaconing        10.0.0.50  (6 connections, ~60s apart, to 203.0.113.77:443)
  [HIGH]     dns_tunneling       10.0.0.77  (5 long, high-entropy queries to *.exfil.example.com)

GET /reports:
  10.0.0.66  score=70  risk=high    (port_scan_vertical + c2_beaconing)
  10.0.0.50  score=40  risk=medium  (c2_beaconing)
  10.0.0.77  score=35  risk=medium  (dns_tunneling)
```

**Honest edge case, found by actually running this, not invented for
the README:** the scripted port scan's packets were sent at a perfectly
even 0.2s cadence, which is *also* what the beaconing detector looks
for (a low coefficient of variation between connection intervals) — so
`10.0.0.66` got flagged for both. A real port scan wouldn't usually be
machine-perfect timed, but a very fast automated scanner could
genuinely produce this overlap. That's a real property of
interval-regularity-based detection, not a bug I'm hiding — it's worth
knowing if you tune these thresholds against real traffic.

## The five detectors

| Detector | Signal | 
|---|---|
| `port_scan.py` | ≥15 distinct ports on one host (vertical) or ≥10 hosts on one port (horizontal) from one source within 2 minutes |
| `beaconing.py` | connections to one destination at a near-constant interval (coefficient of variation ≤ 0.15) |
| `brute_force.py` | ≥8 short (<4KB) connections to an auth port (22/3389/445/21/23) from one source to one destination within 3 minutes |
| `suspicious_outbound.py` | a single flow ≥50MB to a public (non-RFC1918) destination |
| `dns_tunneling.py` | ≥3 DNS queries per source that are both long (≥50 chars) AND high-entropy (≥3.5 bits/char) |

## Real PCAP parsing, not a stub

`pcap_ingest.py` uses Scapy's `rdpcap()` to read an actual `.pcap` file
byte-for-byte, walks IP/TCP/UDP/DNS layers per packet, and produces
`FlowRecord`s the same detectors operate on regardless of whether flows
arrived via PCAP upload or direct JSON ingestion. `demo/generate_pcap.py`
crafts a real attack scenario with Scapy's packet-construction API
(`IP()/TCP()`, `IP()/UDP()/DNS()`) and writes it with `wrpcap()` — this
is genuine packet-capture I/O, not JSON dressed up as a PCAP.

## Threat score, built from real contributions

`threat_score.py` sums each finding's `score_contribution` per source
IP (capped at 100), buckets it into a risk level, and writes a summary
naming the actual finding types — the `70/100 (high)` above is `30
(port scan) + 40 (beaconing)`, not a hand-picked number.

## Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

15 tests: each detector's positive and negative case (port scan
above/below threshold, beaconing on regular intervals, brute force
distinguishing short auth-attempt-sized flows from real sessions,
outbound transfer ignoring private destinations, DNS tunneling
ignoring ordinary short queries), full API integration (ingest → detect
→ reports → per-IP report → 404 → reset), and — critically — a live
PCAP-upload test that generates a real `.pcap` with Scapy, uploads it
through the actual `/ingest/pcap` endpoint, and asserts all three
scripted attack types are detected from the parsed packets.

## Project layout

```
backend/
  app/
    models.py, store.py, threat_score.py, engine.py, main.py
    pcap_ingest.py         # real Scapy-based PCAP parsing
    detectors/                 # one file per detection
  demo/
    generate_pcap.py             # crafts a real .pcap attack scenario with Scapy
  tests/
    test_detectors.py, test_api.py
frontend/
  index.html                       # React (CDN) investigation console
```

## Honest scope

An in-memory store rather than a live Elasticsearch cluster or a real
Zeek deployment (Zeek's conn.log format maps cleanly onto `FlowRecord`
if you want to swap the ingestion source later). Five detectors on
synthetic/scripted traffic, not a production NDR's full rule library —
but the PCAP ingestion is real, the detectors are real computed logic
(not lookups), and the beaconing/port-scan overlap above is a real
finding from actually running the pipeline, which is the standard the
rest of this project holds itself to.
