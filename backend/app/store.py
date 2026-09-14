"""
Minimal in-memory store for ingested flows and computed findings --
swappable for Elasticsearch/OpenSearch the same way ThreatHunt-X's
EventStore is (see that project's store.py for the same pattern).
"""

from typing import List

from app.models import FlowRecord, ThreatFinding


class FlowStore:
    def __init__(self) -> None:
        self.flows: List[FlowRecord] = []
        self.findings: List[ThreatFinding] = []

    def clear(self) -> None:
        self.__init__()


store = FlowStore()
