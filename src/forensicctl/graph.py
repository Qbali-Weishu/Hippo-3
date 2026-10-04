from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations, product
from typing import Iterable

from .config import CaseConfig
from .domain import LineageGraph, split_pipe
from .models import Event


@dataclass(frozen=True)
class Candidate:
    indicator_id: str
    branch: str
    events: tuple[Event, ...]
    lineage: tuple[str, ...]
    score: tuple[int, int, int, int, str]

    @property
    def event_ids(self) -> tuple[str, ...]:
        return tuple(event.event_id for event in self.events)

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(sorted({event.source for event in self.events}))

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted({event.host for event in self.events}))

    @property
    def first_time(self):
        return min(event.normalized_at for event in self.events)

    @property
    def last_time(self):
        return max(event.normalized_at for event in self.events)

    def public(self, decision: str = "eligible") -> dict[str, object]:
        return {
            "candidate_id": self.indicator_id,
            "branch": self.branch,
            "decision": decision,
            "event_ids": list(self.event_ids),
            "sources": list(self.sources),
            "hosts": list(self.hosts),
            "lineage": list(self.lineage),
            "score": list(self.score[:4]),
        }


class EventGraph:
    def __init__(self, events: Iterable[Event]):
        self.events = {event.event_id: event for event in events}
        self.lineage = LineageGraph(self.events.values())

    def lineage_ids(self, event: Event) -> tuple[str, ...]:
        return self.lineage.ids(event)

    def path_for(self, events: Iterable[Event]) -> tuple[str, ...]:
        ids: set[str] = set()
        for event in events:
            ids.update(self.lineage_ids(event))
        return tuple(sorted(ids))

    def connected(self, prior: Candidate, event: Event) -> bool:
        if not event.parent_event_id:
            return False
        return event.parent_event_id in set(prior.lineage) | set(prior.event_ids)


class CandidateResolver:
    def __init__(self, config: CaseConfig, events: list[Event]):
        self.config = config
        self.events = events
        self.graph = EventGraph(events)
        self.window = config.evidence_window
        self.by_indicator: dict[str, list[Candidate]] = {}
        self.rows_by_id = {str(row["candidate_id"]): row for row in config.indicators}

    def _scope_ok(self, event: Event, row: dict[str, object]) -> bool:
        if not self.window.contains(event.normalized_at) or event.status != "success":
            return False
        if event.context in {"routine", "health", "backup", "failed", "cleanup"}:
            return False
        scope_rule = str(row.get("scope_rule", "authorized"))
        if scope_rule == "authorized":
            return (
                self.config.authorized_host(event.host)
                and self.config.principal_allowed_on(event.principal, event.host)
                and event.authorized_identity
            )
        if scope_rule == "linked":
            return bool(event.parent_event_id)
        raise ValueError(f"unsupported scope rule {scope_rule}")

    def _eligible(self, row: dict[str, object]) -> list[Event]:
        allowed = set(split_pipe(row.get("required_sources", "")))
        return [
            event for event in self.events
            if event.kind == str(row.get("required_kind", ""))
            and event.context == str(row.get("required_context", ""))
            and event.source in allowed
            and self._scope_ok(event, row)
        ]

    def _group_key(self, event: Event, row: dict[str, object]) -> tuple[str, ...]:
        keys = split_pipe(row.get("join_keys", "host|principal|peer|context"))
        fields = {
            "host": event.host,
            "principal": event.principal,
            "peer": event.peer,
            "context": event.context,
            "session_id": event.session_id,
            "path": event.path,
            "parent_event_id": event.parent_event_id,
        }
        return tuple(str(fields.get(key, event.raw.get(key, ""))) for key in keys)

    def _quorum_sets(self, values: list[Event], row: dict[str, object]) -> list[tuple[Event, ...]]:
        quorum = int(row["quorum"])
        by_source: dict[str, list[Event]] = defaultdict(list)
        for event in values:
            by_source[event.source].append(event)
        if len(by_source) < quorum:
            return []
        candidates: dict[tuple[str, ...], tuple[Event, ...]] = {}
        for sources in combinations(sorted(by_source), quorum):
            for chosen in product(*(sorted(by_source[source], key=lambda e: e.normalized_key) for source in sources)):
                if len({event.event_id for event in chosen}) != quorum:
                    continue
                ordered = tuple(sorted(chosen, key=lambda e: e.normalized_key))
                candidates[tuple(event.event_id for event in ordered)] = ordered
        return list(candidates.values())

    def _make(self, row: dict[str, object], branch: str, chosen: tuple[Event, ...], parent: Candidate | None = None) -> Candidate:
        lineage = set(self.graph.path_for(chosen))
        if parent:
            lineage.update(parent.lineage)
            lineage.update(parent.event_ids)
        latest = max(event.normalized_at.timestamp() for event in chosen)
        score = (
            len({event.source for event in chosen}),
            len({event.host for event in chosen}),
            len(lineage),
            int(latest),
            "|".join(event.event_id for event in chosen),
        )
        return Candidate(str(row["candidate_id"]), branch, chosen, tuple(sorted(lineage)), score)

    def _root_candidates(self, row: dict[str, object]) -> list[Candidate]:
        groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
        for event in self._eligible(row):
            groups[self._group_key(event, row)].append(event)
        return [self._make(row, str(row["candidate_id"]), chosen) for values in groups.values() for chosen in self._quorum_sets(values, row)]

    def _linked_candidates(self, row: dict[str, object], predecessors: list[Candidate]) -> list[Candidate]:
        result: list[Candidate] = []
        for predecessor in predecessors:
            values = [
                event for event in self._eligible(row)
                if self.graph.connected(predecessor, event)
                and event.normalized_at >= predecessor.last_time
            ]
            groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
            for event in values:
                groups[self._group_key(event, row)].append(event)
            for values in groups.values():
                for chosen in self._quorum_sets(values, row):
                    result.append(self._make(row, predecessor.branch, chosen, predecessor))
        unique = {candidate.event_ids + (candidate.branch,): candidate for candidate in result}
        return list(unique.values())

    def _indicator_order(self) -> list[dict[str, object]]:
        rows = {str(row["candidate_id"]): row for row in self.config.indicators}
        indegree = {key: 0 for key in rows}
        children: dict[str, set[str]] = defaultdict(set)
        for key, row in rows.items():
            predecessor = str(row.get("predecessor", ""))
            if predecessor:
                if predecessor not in rows:
                    raise ValueError(f"indicator references unknown predecessor {predecessor}")
                indegree[key] += 1
                children[predecessor].add(key)
        ready = sorted(key for key, degree in indegree.items() if degree == 0)
        result: list[dict[str, object]] = []
        while ready:
            key = ready.pop(0)
            result.append(rows[key])
            for child in sorted(children[key]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
            ready.sort()
        if len(result) != len(rows):
            raise ValueError("indicator predecessor graph contains a cycle")
        return result

    def _complete_paths(self, rows: list[dict[str, object]]) -> list[dict[str, Candidate]]:
        terminals = {str(row["candidate_id"]) for row in rows if not any(str(child.get("predecessor", "")) == str(row["candidate_id"]) for child in rows)}
        paths: list[dict[str, Candidate]] = []
        for terminal in terminals:
            for candidate in self.by_indicator.get(terminal, []):
                path: dict[str, Candidate] = {terminal: candidate}
                current = terminal
                while True:
                    predecessor = str(self.rows_by_id[current].get("predecessor", ""))
                    if not predecessor:
                        break
                    choices = [item for item in self.by_indicator.get(predecessor, []) if item.branch == candidate.branch and set(item.event_ids).issubset(set(candidate.lineage) | set(candidate.event_ids))]
                    if not choices:
                        break
                    chosen = max(choices, key=lambda item: item.score)
                    path[predecessor] = chosen
                    current = predecessor
                if len(path) == len(rows):
                    paths.append(path)
        return paths

    def resolve(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        rows = self._indicator_order()
        matrix: list[dict[str, object]] = []
        for row in rows:
            identifier = str(row["candidate_id"])
            predecessor = str(row.get("predecessor", ""))
            candidates = self._linked_candidates(row, self.by_indicator.get(predecessor, [])) if predecessor else self._root_candidates(row)
            candidates.sort(key=lambda item: (item.branch, item.score), reverse=True)
            self.by_indicator[identifier] = candidates
            matrix.append({
                "candidate_id": identifier,
                "phase": row.get("phase", ""),
                "decision": "eligible" if candidates else "rejected",
                "candidate_count": len(candidates),
                "candidates": [candidate.public() for candidate in candidates],
            })
        complete = self._complete_paths(rows)
        if not complete:
            raise ValueError("no complete evidence chain satisfies the configured lineage and quorum rules")
        def path_score(path: dict[str, Candidate]) -> tuple[int, int, int, int, str]:
            events = {event_id for candidate in path.values() for event_id in candidate.event_ids}
            candidates = list(path.values())
            return (
                len({event.source for candidate in candidates for event in candidate.events}),
                len({event.host for candidate in candidates for event in candidate.events}),
                len(events),
                int(max(candidate.last_time.timestamp() for candidate in candidates)),
                "|".join(sorted(events)),
            )
        complete.sort(key=path_score, reverse=True)
        if len(complete) > 1 and path_score(complete[0])[:4] == path_score(complete[1])[:4]:
            raise ValueError("multiple complete evidence chains remain tied after global arbitration")
        selected_path = complete[0]
        selected = []
        for row in rows:
            identifier = str(row["candidate_id"])
            candidate = selected_path[identifier]
            selected.append({
                "candidate_id": identifier,
                "branch": candidate.branch,
                "event_ids": list(candidate.event_ids),
                "sources": list(candidate.sources),
                "lineage": list(candidate.lineage),
            })
        selected_ids = {row["candidate_id"] for row in selected}
        for row in matrix:
            candidates = row["candidates"]
            for candidate in candidates:
                if candidate["candidate_id"] == row["candidate_id"] and candidate["branch"] == selected_path[row["candidate_id"]].branch and set(candidate["event_ids"]) == set(selected_path[row["candidate_id"]].event_ids):
                    candidate["decision"] = "accept"
                else:
                    candidate["decision"] = "reject"
        return matrix, selected


def correlate(config: CaseConfig, events: list[Event]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    return CandidateResolver(config, events).resolve()
