from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .config import CaseConfig
from .domain import LineageGraph, split_pipe
from .models import Event


def validate_event_set(config: CaseConfig, events: Iterable[Event]) -> None:
    by_id: dict[str, Event] = {}
    for event in events:
        if event.event_id in by_id:
            raise ValueError(f"duplicate event identity {event.event_id}")
        by_id[event.event_id] = event
        if not event.host:
            raise ValueError(f"event {event.event_id} has no host identity")
    for event in by_id.values():
        if event.parent_event_id and event.parent_event_id not in by_id:
            raise ValueError(f"event {event.event_id} references missing parent {event.parent_event_id}")
        if event.parent_event_id == event.event_id:
            raise ValueError(f"event {event.event_id} references itself")

    LineageGraph(by_id.values())

    for event in by_id.values():
        if event.parent_event_id:
            parent = by_id[event.parent_event_id]
            if (
                config.evidence_window.contains(parent.normalized_at)
                and config.evidence_window.contains(event.normalized_at)
                and parent.normalized_at - event.normalized_at > timedelta(seconds=30)
            ):
                raise ValueError(f"event {event.event_id} occurs before its parent")


def validate_candidate_catalog(config: CaseConfig) -> None:
    ids = [row["candidate_id"] for row in config.indicators]
    if len(ids) != len(set(ids)):
        raise ValueError("indicator candidate ids must be unique")
    known = set(ids)
    for row in config.indicators:
        config.evidence_contract.validate_indicator(row)
        predecessor = row.get("predecessor", "")
        if predecessor and predecessor not in known:
            raise ValueError(f"indicator references unknown predecessor {predecessor}")
        if int(row["quorum"]) < 1 or int(row["quorum"]) > len(split_pipe(row["required_sources"])):
            raise ValueError(f"invalid quorum for {row['candidate_id']}")


def validate_action_catalog(config: CaseConfig) -> None:
    catalog = config.action_catalog
    required = config.required_action_ids()
    if not required.issubset(catalog):
        raise ValueError("required action is absent from action catalog")
    for action_id, row in catalog.items():
        if int(row["minutes"]) <= 0:
            raise ValueError(f"action {action_id} has invalid duration")
        for dependency in filter(None, str(row.get("requires", "")).split("|")):
            if dependency not in catalog:
                raise ValueError(f"action {action_id} references unknown prerequisite {dependency}")
        if str(row.get("approval", "")).strip() == "" or str(row.get("rollback", "")).strip() == "":
            raise ValueError(f"action {action_id} has incomplete governance metadata")
    graph: dict[str, set[str]] = defaultdict(set)
    for before, after in config.iter_dependency_edges():
        graph[after].add(before)
    remaining = set(catalog)
    while remaining:
        ready = {item for item in remaining if not graph[item] & remaining}
        if not ready:
            raise ValueError("action dependency graph contains a cycle")
        remaining -= ready
