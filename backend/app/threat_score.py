"""
Aggregates every finding for a source IP into a single InvestigationReport:
a 0-100 threat score (sum of each finding's score_contribution, capped),
a risk level bucket, and a human-readable summary -- the actual
"investigation report" deliverable, built from real per-finding
contributions rather than a hand-picked number.
"""

from typing import Dict, List

from app.models import ThreatFinding, InvestigationReport

RISK_LEVEL_THRESHOLDS = [(80, "critical"), (55, "high"), (25, "medium"), (0, "low")]


def _risk_level(score: int) -> str:
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def build_investigation_reports(all_findings: List[ThreatFinding]) -> Dict[str, InvestigationReport]:
    by_source: Dict[str, List[ThreatFinding]] = {}
    for f in all_findings:
        by_source.setdefault(f.source_ip, []).append(f)

    reports = {}
    for source_ip, findings in by_source.items():
        raw_score = sum(f.score_contribution for f in findings)
        score = min(100, raw_score)
        risk_level = _risk_level(score)

        finding_types = sorted({f.finding_type for f in findings})
        summary = (
            f"{source_ip} triggered {len(findings)} finding(s) across "
            f"{len(finding_types)} categor{'y' if len(finding_types) == 1 else 'ies'} "
            f"({', '.join(finding_types)}) -- threat score {score}/100 ({risk_level})."
        )

        reports[source_ip] = InvestigationReport(
            source_ip=source_ip, threat_score=score, risk_level=risk_level,
            findings=findings, summary=summary,
        )

    return reports
