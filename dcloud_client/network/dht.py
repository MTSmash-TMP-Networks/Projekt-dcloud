"""Lightweight Kademlia-like peer index for dcloud discovery."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable


@dataclass
class DhtRecord:
    node_id: str
    host: str
    udp_port: int
    seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DhtIndex:
    def __init__(self, k: int = 20) -> None:
        self.k = max(8, int(k))
        self._records: dict[str, DhtRecord] = {}

    def upsert(self, node_id: str, host: str, udp_port: int) -> None:
        self._records[node_id] = DhtRecord(node_id=node_id, host=host, udp_port=int(udp_port))

    def nearest(self, target_node_id: str) -> list[DhtRecord]:
        def distance(a: str, b: str) -> int:
            try:
                return int(a[:32], 16) ^ int(b[:32], 16)
            except Exception:
                return abs(hash(a) - hash(b))
        return sorted(self._records.values(), key=lambda r: distance(r.node_id, target_node_id))[: self.k]

    def export(self) -> list[dict[str, object]]:
        return [{"node_id":r.node_id,"host":r.host,"udp_port":r.udp_port} for r in self._records.values()]

    def ingest(self, entries: Iterable[dict[str, object]]) -> None:
        for item in entries:
            node_id = str(item.get('node_id',''))
            host = str(item.get('host',''))
            try:
                port = int(item.get('udp_port',0))
            except Exception:
                port = 0
            if node_id and host and 1 <= port <= 65535:
                self.upsert(node_id, host, port)
