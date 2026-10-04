from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Sequence


def split_pipe(value: object) -> tuple[str, ...]:
    return tuple(part.strip() for part in str(value or "").split("|") if part.strip())


def split_csv(value: object) -> tuple[str, ...]:
    return tuple(part.strip() for part in str(value or "").split(",") if part.strip())


def positive_int(value: object, field: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if number < 0:
        raise ValueError(f"{field} must not be negative")
    return number


@dataclass(frozen=True)
class EvidenceIdentity:
    event_id: str
    source: str
    clock_segment: str
    observed_at: str
    host: str
    kind: str
    context: str
    status: str
    principal: str
    peer: str
    path: str
    parent_event_id: str
    bytes_out: int

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "EvidenceIdentity":
        return cls(
            event_id=str(payload.get("event_id", "")),
            source=str(payload.get("source", "")),
            clock_segment=str(payload.get("clock_segment", "")),
            observed_at=str(payload.get("observed_at", "")),
            host=str(payload.get("host", "")),
            kind=str(payload.get("kind", "")),
            context=str(payload.get("context", "")),
            status=str(payload.get("status", "")),
            principal=str(payload.get("principal", "")),
            peer=str(payload.get("peer", "")),
            path=str(payload.get("path", "")),
            parent_event_id=str(payload.get("parent_event_id", "")),
            bytes_out=positive_int(payload.get("bytes_out", 0) or 0, "bytes_out"),
        )

    def comparable(self) -> tuple[object, ...]:
        return (
            self.source,
            self.clock_segment,
            self.observed_at,
            self.host,
            self.kind,
            self.context,
            self.status,
            self.principal,
            self.peer,
            self.path,
            self.parent_event_id,
            self.bytes_out,
        )


@dataclass(frozen=True)
class EvidenceWindow:
    start: datetime
    end: datetime

    def contains(self, value: datetime) -> bool:
        return self.start <= value < self.end

    def duration(self) -> timedelta:
        return self.end - self.start


class LineageGraph:
    def __init__(self, events: Iterable[Any]):
        self.events = {event.event_id: event for event in events}
        self.parents = {
            event.event_id: event.parent_event_id
            for event in self.events.values()
            if event.parent_event_id
        }
        self.children: dict[str, list[Any]] = defaultdict(list)
        for event in self.events.values():
            if event.parent_event_id:
                self.children[event.parent_event_id].append(event)
        for rows in self.children.values():
            rows.sort(key=lambda item: (item.normalized_at, item.event_id))

    def ancestors(self, event: Any) -> tuple[Any, ...]:
        result: list[Any] = []
        seen: set[str] = set()
        current = event.parent_event_id
        while current:
            if current in seen:
                raise ValueError(f"event lineage cycle at {event.event_id}")
            seen.add(current)
            parent = self.events.get(current)
            if parent is None:
                raise ValueError(f"event {event.event_id} references missing parent {current}")
            result.append(parent)
            current = parent.parent_event_id
        return tuple(result)

    def ids(self, event: Any) -> tuple[str, ...]:
        return tuple(item.event_id for item in self.ancestors(event)) + (event.event_id,)

    def path_to(self, ancestor_id: str, event: Any) -> tuple[Any, ...]:
        path = list(reversed(self.ancestors(event))) + [event]
        for index, item in enumerate(path):
            if item.event_id == ancestor_id:
                return tuple(path[index:])
        return ()

    def shares_ancestor(self, left: Any, right: Any) -> bool:
        return bool(set(self.ids(left)) & set(self.ids(right)))

    def reachable(self, start_id: str, allowed: set[str] | None = None) -> tuple[Any, ...]:
        queue = deque([start_id])
        visited: set[str] = set()
        result: list[Any] = []
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for child in self.children.get(current, []):
                if allowed is None or child.event_id in allowed:
                    result.append(child)
                    queue.append(child.event_id)
        return tuple(result)


class CandidateEvidence:
    def __init__(self, events: Sequence[Any]):
        self.events = tuple(events)
        self.sources = frozenset(event.source for event in events)
        self.hosts = frozenset(event.host for event in events)
        self.principals = frozenset(event.principal for event in events)
        self.contexts = frozenset(event.context for event in events)

    def has_quorum(self, quorum: int) -> bool:
        return len(self.sources) >= quorum

    def ordered_ids(self) -> list[str]:
        return [event.event_id for event in sorted(self.events, key=lambda item: (item.normalized_at, item.event_id))]

    def time_span(self) -> tuple[datetime | None, datetime | None]:
        if not self.events:
            return None, None
        ordered = sorted(self.events, key=lambda item: item.normalized_at)
        return ordered[0].normalized_at, ordered[-1].normalized_at


class DependencyState:
    def __init__(self, catalog: Mapping[str, Mapping[str, Any]], selected: Sequence[str]):
        self.catalog = catalog
        self.selected = tuple(selected)
        self.position = {action_id: index for index, action_id in enumerate(self.selected)}

    def requirements(self, action_id: str) -> tuple[str, ...]:
        row = self.catalog.get(action_id, {})
        return split_pipe(row.get("requires", ""))

    def unmet(self, action_id: str) -> tuple[str, ...]:
        position = self.position.get(action_id, len(self.selected))
        return tuple(
            requirement
            for requirement in self.requirements(action_id)
            if requirement not in self.position or self.position[requirement] >= position
        )

    def edges(self, include_unselected: bool = False) -> dict[str, set[str]]:
        ids = set(self.catalog) if include_unselected else set(self.selected)
        graph = {action_id: set() for action_id in ids}
        for action_id in ids:
            graph[action_id].update(dep for dep in self.requirements(action_id) if dep in ids)
        return graph

    def topological_order(self, ids: Iterable[str] | None = None) -> list[str]:
        chosen = set(ids if ids is not None else self.selected)
        graph = {key: value & chosen for key, value in self.edges().items() if key in chosen}
        result: list[str] = []
        while graph:
            ready = sorted(key for key, deps in graph.items() if not deps)
            if not ready:
                raise ValueError("action dependency graph contains a cycle")
            result.extend(ready)
            for key in ready:
                graph.pop(key)
            for deps in graph.values():
                deps.difference_update(ready)
        return result

    def capabilities(self) -> set[str]:
        return {
            str(self.catalog[action_id].get("provides", ""))
            for action_id in self.selected
            if action_id in self.catalog and self.catalog[action_id].get("provides")
        }

    def conflicts(self) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        active: set[str] = set()
        for action_id in self.selected:
            row = self.catalog.get(action_id, {})
            for conflict in split_pipe(row.get("conflicts", "")):
                if conflict in active:
                    found.append((action_id, conflict))
            if row.get("provides"):
                active.add(str(row["provides"]))
        return found
