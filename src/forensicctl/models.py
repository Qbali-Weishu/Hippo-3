from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    event_id: str
    source: str
    clock_segment: str
    observed_at: datetime
    normalized_at: datetime
    kind: str
    context: str
    status: str
    host: str
    principal: str
    peer: str
    path: str
    parent_event_id: str
    bytes_out: int
    evidence_file: str
    raw: dict[str, Any] = field(compare=False, repr=False)

    @property
    def successful(self) -> bool:
        return self.status == "success"

    @property
    def direction(self) -> str:
        explicit = str(self.raw.get("direction", "")).strip().lower()
        if explicit in {"inbound", "outbound", "internal"}:
            return explicit
        if self.kind == "tls_transfer":
            return "outbound" if self.peer else "internal"
        return "internal"

    @property
    def session_id(self) -> str:
        explicit = str(self.raw.get("session_id", "")).strip()
        return explicit or f"{self.context}|{self.host}|{self.peer}|{self.principal}"

    @property
    def trace_id(self) -> str:
        return str(self.raw.get("trace_id", "")).strip()

    @property
    def artifact(self) -> str:
        return str(self.raw.get("artifact", self.path)).strip()

    @property
    def confidence(self) -> str:
        value = str(self.raw.get("confidence", "low")).strip().lower()
        return value if value in {"low", "medium", "high"} else "low"

    @property
    def integrity(self) -> str:
        value = str(self.raw.get("integrity", "partial")).strip().lower()
        return value if value in {"sealed", "partial", "untrusted"} else "untrusted"

    @property
    def causal(self) -> bool:
        value = self.raw.get("causal", False)
        return value is True or str(value).strip().lower() in {"true", "1", "yes"}

    @property
    def operation(self) -> str:
        return str(self.raw.get("operation", self.kind)).strip()

    @property
    def authorization_basis(self) -> str:
        return str(self.raw.get("authorization_basis", "")).strip()

    @property
    def normalized_key(self) -> tuple[datetime, str]:
        return self.normalized_at, self.event_id

    @property
    def authorized_identity(self) -> bool:
        value = self.raw.get("authorized", True)
        return value is True or str(value).strip().lower() in {"true", "1", "yes"}

    def lineage_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "parent_event_id": self.parent_event_id,
            "source": self.source,
            "context": self.context,
            "host": self.host,
            "principal": self.principal,
            "normalized_time": self.normalized_at.isoformat().replace("+00:00", "Z"),
        }

    def public(self) -> dict[str, Any]:
        value = dict(self.raw)
        value["normalized_time"] = self.normalized_at.isoformat().replace("+00:00", "Z")
        value["evidence_file"] = self.evidence_file
        return value
