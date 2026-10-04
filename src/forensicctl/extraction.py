from __future__ import annotations

from pathlib import Path

from .config import CaseConfig
from .audit import EvidenceAudit
from .ingest import load_events
from .serialization import atomic_output_dir, write_json, write_jsonl


class ExtractionWriter:
    def __init__(self, config: CaseConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir

    def _summary(self, events, clocks, counts) -> dict[str, object]:
        return {
            "case_id": self.config.case_id,
            "event_count": len(events),
            "unique_event_count": len({event.event_id for event in events}),
            "shard_count": len(counts),
            "shard_counts": counts,
            "clock_models": clocks.public(),
            "normalized_order": "utc_then_event_id",
            "audit": EvidenceAudit(events, self.config.evidence_contract.source_names).public(),
        }

    def write(self) -> dict[str, object]:
        events, clocks, counts = load_events(self.config)
        summary = self._summary(events, clocks, counts)
        with atomic_output_dir(self.output_dir) as staging:
            write_jsonl(staging / "normalized_events.jsonl", (event.public() for event in events))
            write_json(staging / "shard_counts.json", counts)
            write_json(staging / "extraction_summary.json", summary)
        return summary


def extract(config: CaseConfig, output_dir: Path) -> dict[str, object]:
    return ExtractionWriter(config, output_dir).write()
