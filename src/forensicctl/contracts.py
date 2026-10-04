from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .domain import split_pipe


@dataclass(frozen=True)
class IncidentWindow:
    start: datetime
    end: datetime

    def contains(self, value: datetime) -> bool:
        return self.start <= value < self.end

    def validate(self) -> None:
        if self.start >= self.end:
            raise ValueError("incident window must have a positive duration")


@dataclass(frozen=True)
class EvidenceContract:
    required_fields: tuple[str, ...]
    source_names: tuple[str, ...]
    manifest_counts: tuple[tuple[str, int], ...]
    window: IncidentWindow
    contextual_join_keys: tuple[str, ...] = ()

    @classmethod
    def from_document(cls, document: dict[str, Any], parse_time) -> "EvidenceContract":
        schema = document["event_schema"]
        manifest = tuple(
            sorted(
                (str(row["filename"]), int(row["record_count"]))
                for row in document["evidence_manifest"]
            )
        )
        scope = document["case"]
        start, end = (parse_time(value) for value in scope["incident_window"])
        contract = cls(
            required_fields=tuple(str(field) for field in schema["required_event_fields"]),
            source_names=tuple(sorted(str(row["source"]) for row in document["evidence_manifest"])),
            manifest_counts=manifest,
            window=IncidentWindow(start, end),
            contextual_join_keys=tuple(str(item) for item in schema.get("contextual_join_keys", ())),
        )
        contract.validate()
        return contract

    def validate(self) -> None:
        if not self.required_fields:
            raise ValueError("event contract has no required fields")
        if not self.source_names or len(set(self.source_names)) != len(self.source_names):
            raise ValueError("event contract has duplicate or missing sources")
        if any(count < 1 for _, count in self.manifest_counts):
            raise ValueError("evidence manifest contains an empty source")
        if len(set(self.required_fields)) != len(self.required_fields):
            raise ValueError("event contract contains duplicate required fields")
        if not set(self.contextual_join_keys).issubset(
            set(self.required_fields)
            | {"principal", "peer", "parent_event_id", "session_id", "artifact", "operation"}
        ):
            raise ValueError("event contract contains unknown join keys")
        self.window.validate()

    def expected_counts(self) -> dict[str, int]:
        return dict(self.manifest_counts)

    def validate_counts(self, counts: dict[str, int]) -> None:
        if counts != self.expected_counts():
            raise ValueError(f"evidence manifest counts do not match: expected {self.expected_counts()}, got {counts}")

    def validate_payload(self, payload: dict[str, Any]) -> None:
        missing = [field for field in self.required_fields if field not in payload]
        if missing:
            event_id = payload.get("event_id", "<unknown>")
            raise ValueError(f"event {event_id} missing fields: {', '.join(missing)}")
        if str(payload.get("source", "")) not in self.source_names:
            raise ValueError(f"unknown evidence source: {payload.get('source')}")
        for field in ("event_id", "source", "clock_segment", "observed_at", "host", "kind", "context", "status"):
            if not isinstance(payload.get(field), str) or not payload[field].strip():
                raise ValueError(f"event field {field} must be a non-empty string")
        if "bytes_out" in payload:
            try:
                if int(payload["bytes_out"]) < 0:
                    raise ValueError("bytes_out must not be negative")
            except (TypeError, ValueError) as exc:
                raise ValueError("bytes_out must be a non-negative integer") from exc
        if str(payload.get("status")) not in {"success", "failed", "denied"}:
            raise ValueError(f"event has unsupported status: {payload.get('status')}")

    def validate_indicator(self, indicator: dict[str, Any]) -> None:
        required = {"candidate_id", "phase", "required_kind", "required_context", "required_sources", "quorum", "predecessor", "scope_rule"}
        missing = required - set(indicator)
        if missing:
            raise ValueError("indicator missing fields: " + ", ".join(sorted(missing)))
        sources = split_pipe(indicator["required_sources"])
        if not sources or not set(sources).issubset(set(self.source_names)):
            raise ValueError(f"indicator {indicator['candidate_id']} references an unknown source")
        quorum = int(indicator["quorum"])
        if quorum < 1 or quorum > len(sources):
            raise ValueError(f"indicator {indicator['candidate_id']} has impossible quorum")
        if indicator["scope_rule"] not in {"authorized", "linked"}:
            raise ValueError(f"indicator {indicator['candidate_id']} has unsupported scope rule")

    def normalize_source_set(self, value: str | Iterable[str]) -> set[str]:
        if isinstance(value, str):
            return {part.strip() for part in value.split("|") if part.strip()}
        return {str(part).strip() for part in value if str(part).strip()}

    def check_window(self, value: datetime) -> None:
        if not self.window.contains(value):
            raise ValueError("event falls outside the authorized incident window")
