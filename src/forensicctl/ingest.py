from __future__ import annotations

from collections import Counter
from pathlib import Path

from .clock import ClockRegistry, parse_time
from .config import CaseConfig
from .domain import EvidenceIdentity, positive_int
from .models import Event
from .repository import EvidenceRepository
from .validation import validate_event_set


def _event(raw: dict, source_file: str, clocks: ClockRegistry) -> Event:
    source = str(raw["source"])
    segment = str(raw["clock_segment"])
    observed = parse_time(str(raw["observed_at"]))
    return Event(
        event_id=str(raw["event_id"]),
        source=source,
        clock_segment=segment,
        observed_at=observed,
        normalized_at=clocks.normalize(source, segment, observed),
        kind=str(raw.get("kind", "")),
        context=str(raw.get("context", "")),
        status=str(raw.get("status", "")),
        host=str(raw.get("host", "")),
        principal=str(raw.get("principal", "")),
        peer=str(raw.get("peer", "")),
        path=str(raw.get("path", "")),
        parent_event_id=str(raw.get("parent_event_id", "")),
        bytes_out=positive_int(raw.get("bytes_out", 0) or 0, "bytes_out"),
        evidence_file=source_file,
        raw=dict(raw),
    )


def load_events(config: CaseConfig) -> tuple[list[Event], ClockRegistry, dict[str, int]]:
    repository = EvidenceRepository(config)
    clocks = ClockRegistry.from_rows(config.clock_sync)
    counts: Counter[str] = Counter()
    events: dict[str, Event] = {}
    identities: dict[str, EvidenceIdentity] = {}
    for record in repository.records():
        repository.validate_record_shape(record)
        counts[record.source_file] += 1
        event = _event(record.payload, record.source_file, clocks)
        identity = EvidenceIdentity.from_payload(record.payload)
        previous = events.get(event.event_id)
        if previous is not None:
            if identities[event.event_id].comparable() != identity.comparable():
                raise ValueError(f"conflicting duplicate event {event.event_id}")
            continue
        events[event.event_id] = event
        identities[event.event_id] = identity
    config.validate_manifest_counts(dict(sorted(counts.items())))
    validate_event_set(config, events.values())
    ordered = sorted(events.values(), key=lambda item: item.normalized_key)
    return ordered, clocks, dict(sorted(counts.items()))
