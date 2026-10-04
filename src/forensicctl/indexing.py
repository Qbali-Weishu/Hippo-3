from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import Event
from .domain import LineageGraph


@dataclass(frozen=True)
class EventKey:
    kind: str
    context: str
    source: str


class EventIndex:
    def __init__(self, events: Iterable[Event]):
        self.events = {event.event_id: event for event in events}
        self.by_source: dict[str, list[Event]] = defaultdict(list)
        self.by_kind: dict[str, list[Event]] = defaultdict(list)
        self.by_context: dict[str, list[Event]] = defaultdict(list)
        self.children: dict[str, list[Event]] = defaultdict(list)
        self.by_host: dict[str, list[Event]] = defaultdict(list)
        self.by_principal: dict[str, list[Event]] = defaultdict(list)
        self.by_session: dict[str, list[Event]] = defaultdict(list)
        for event in self.events.values():
            self.by_source[event.source].append(event)
            self.by_kind[event.kind].append(event)
            self.by_context[event.context].append(event)
            self.by_host[event.host].append(event)
            self.by_principal[event.principal].append(event)
            self.by_session[event.session_id].append(event)
            if event.parent_event_id:
                self.children[event.parent_event_id].append(event)
        for bucket in (self.by_source, self.by_kind, self.by_context, self.children, self.by_host, self.by_principal, self.by_session):
            for key in bucket:
                bucket[key].sort(key=lambda item: (item.normalized_at, item.event_id))

    def get(self, event_id: str) -> Event | None:
        return self.events.get(event_id)

    def select(self, *, kind: str | None = None, context: str | None = None, sources: set[str] | None = None) -> list[Event]:
        if kind is not None and context is not None:
            candidates = list(self.by_context.get(context, []))
        elif kind is not None:
            candidates = list(self.by_kind.get(kind, []))
        elif context is not None:
            candidates = list(self.by_context.get(context, []))
        else:
            candidates = list(self.events.values())
        return [
            event for event in candidates
            if (kind is None or event.kind == kind)
            and (context is None or event.context == context)
            and (sources is None or event.source in sources)
        ]

    def ancestors(self, event: Event) -> tuple[Event, ...]:
        return LineageGraph(self.events.values()).ancestors(event)

    def lineage_ids(self, event: Event) -> set[str]:
        return {item.event_id for item in self.ancestors(event)} | {event.event_id}

    def shares_lineage(self, left: Event, right: Event) -> bool:
        return bool(self.lineage_ids(left) & self.lineage_ids(right))

    def parents_for(self, event: Event) -> tuple[Event, ...]:
        return tuple(self.get(event.parent_event_id),) if self.get(event.parent_event_id) else ()

    def source_count(self, events: Iterable[Event]) -> int:
        return len({event.source for event in events})

    def descendants(self, event: Event) -> tuple[Event, ...]:
        graph = LineageGraph(self.events.values())
        return graph.reachable(event.event_id)

    def path_between(self, ancestor: Event, descendant: Event) -> tuple[Event, ...]:
        graph = LineageGraph(self.events.values())
        return graph.path_to(ancestor.event_id, descendant)

    def session_events(self, session_id: str) -> tuple[Event, ...]:
        return tuple(self.by_session.get(session_id, ()))
