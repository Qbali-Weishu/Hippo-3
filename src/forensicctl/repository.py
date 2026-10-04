from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .config import CaseConfig, ConfigurationError


@dataclass(frozen=True)
class RawRecord:
    payload: dict
    source_file: str
    line_number: int


class EvidenceRepository:
    """Read-only access layer for the evidence collection."""

    def __init__(self, config: CaseConfig):
        self.config = config

    def records(self) -> Iterator[RawRecord]:
        manifest = self.config.evidence_manifest
        seen_paths: set[Path] = set()
        for path in self.config.evidence_paths():
            resolved = path.resolve()
            if resolved in seen_paths or self.config.root.resolve() not in resolved.parents:
                raise ConfigurationError(f"unsafe or repeated evidence path: {path.name}")
            seen_paths.add(resolved)
            if path.name != Path(manifest[str(path.relative_to(self.config.root))]["filename"]).name:
                raise ConfigurationError(f"manifest path mismatch: {path.name}")
            if not path.is_file():
                raise ConfigurationError(f"manifest evidence is missing: {path.name}")
            with path.open() as handle:
                for line_number, line in enumerate(handle, 1):
                    if not line.strip():
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ConfigurationError(f"invalid evidence JSON at {path.name}:{line_number}") from exc
                    if not isinstance(payload, dict):
                        raise ConfigurationError(f"evidence row is not an object at {path.name}:{line_number}")
                    declared_source = str(manifest[str(path.relative_to(self.config.root))]["source"])
                    if str(payload.get("source", "")) != declared_source:
                        raise ConfigurationError(f"evidence source does not match manifest at {path.name}:{line_number}")
                    yield RawRecord(payload, str(path.relative_to(self.config.root)), line_number)

    def counts(self) -> dict[str, int]:
        result = {str(path.relative_to(self.config.root)): 0 for path in self.config.evidence_paths()}
        for record in self.records():
            result[record.source_file] += 1
        self.config.validate_manifest_counts(result)
        return dict(sorted(result.items()))

    def validate_record_shape(self, record: RawRecord) -> None:
        declared_source = self.config.evidence_manifest[record.source_file]["source"]
        if str(record.payload["source"]) != str(declared_source):
            raise ValueError("event source does not match evidence manifest")
        try:
            self.config.evidence_contract.validate_payload(record.payload)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc

    def snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.config.root)): path.read_bytes()
            for path in [self.config.root / "case.json", *self.config.evidence_paths()]
        }
