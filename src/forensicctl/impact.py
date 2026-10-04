from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Event


def _selected_ids(chain: Iterable[dict[str, object]]) -> set[str]:
    return {str(event_id) for row in chain for event_id in row.get("event_ids", [])}


def _session_key(event: Event) -> tuple[str, str, str, str]:
    raw = event.raw
    return (
        str(raw.get("session_id", "")) or event.session_id,
        str(raw.get("transfer_id", "")),
        event.peer,
        event.host,
    )


def _valid_tls(event: Event, selected: set[str]) -> bool:
    return (
        event.event_id in selected
        and event.kind == "tls_transfer"
        and event.successful
        and event.direction == "outbound"
        and event.peer != ""
        and event.bytes_out > 0
        and str(event.raw.get("payload_type", "payload")) == "payload"
        and str(event.raw.get("protocol", "tls")).lower() == "tls"
    )


def quantify(events: list[Event], chain: list[dict[str, object]]) -> dict[str, object]:
    selected = _selected_ids(chain)
    sessions: dict[tuple[str, str, str, str], list[Event]] = defaultdict(list)
    for event in events:
        if _valid_tls(event, selected):
            sessions[_session_key(event)].append(event)
    ledger: list[dict[str, object]] = []
    total = 0
    for key, observations in sorted(sessions.items(), key=lambda item: item[0]):
        canonical = max(observations, key=lambda event: (event.bytes_out, event.source, event.event_id))
        total += canonical.bytes_out
        ledger.append({
            "session_id": key[0],
            "transfer_id": key[1],
            "peer": key[2],
            "host": key[3],
            "event_ids": sorted(event.event_id for event in observations),
            "observed_sources": sorted({event.source for event in observations}),
            "payload_bytes": canonical.bytes_out,
            "canonical_event_id": canonical.event_id,
        })
    hosts = sorted({row["host"] for row in ledger})
    principals = sorted({event.principal for event in events if event.event_id in selected and event.kind == "tls_transfer" and event.successful})
    peers = sorted({row["peer"] for row in ledger})
    return {
        "selected_event_count": len(selected),
        "tls_sessions": ledger,
        "total_outbound_payload_bytes": total,
        "affected_hosts": hosts,
        "affected_principals": principals,
        "external_peers": peers,
        "accounting_rules": {
            "deduplicate_by": ["session_id", "transfer_id", "peer", "host"],
            "count_field": "bytes_out",
            "exclude": ["non-selected-events", "failed", "denied", "inbound", "smb", "protocol-overhead"],
        },
    }
