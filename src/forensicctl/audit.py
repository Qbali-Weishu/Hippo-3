from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .domain import LineageGraph, split_pipe
from .models import Event
from .policy import ActionPolicy


@dataclass(frozen=True)
class AuditIssue:
    code: str
    severity: str
    subject: str
    detail: str

    def public(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "subject": self.subject,
            "detail": self.detail,
        }


class EvidenceAudit:
    def __init__(self, events: Iterable[Event], required_sources: Iterable[str]):
        self.events = tuple(events)
        self.required_sources = tuple(sorted(set(required_sources)))
        self.lineage = LineageGraph(self.events)

    def source_stats(self) -> list[dict[str, Any]]:
        buckets: dict[str, list[Event]] = defaultdict(list)
        for event in self.events:
            buckets[event.source].append(event)
        rows = []
        for source in sorted(buckets):
            values = buckets[source]
            rows.append({
                "source": source,
                "events": len(values),
                "success": sum(event.successful for event in values),
                "failed": sum(event.status == "failed" for event in values),
                "denied": sum(event.status == "denied" for event in values),
                "hosts": sorted({event.host for event in values}),
                "kinds": dict(sorted(Counter(event.kind for event in values).items())),
            })
        return rows

    def lineage_stats(self) -> dict[str, Any]:
        depths: list[int] = []
        roots = 0
        leaves = 0
        for event in self.events:
            ancestors = self.lineage.ancestors(event)
            depths.append(len(ancestors))
            roots += not event.parent_event_id
            leaves += not self.lineage.children.get(event.event_id)
        return {
            "roots": roots,
            "leaves": leaves,
            "max_depth": max(depths, default=0),
            "average_depth": round(sum(depths) / len(depths), 3) if depths else 0,
        }

    def issues(self) -> list[AuditIssue]:
        issues: list[AuditIssue] = []
        observed = {event.source for event in self.events}
        for source in self.required_sources:
            if source not in observed:
                issues.append(AuditIssue("missing-source", "error", source, "required source produced no events"))
        for event in self.events:
            if event.status == "success" and event.host == "":
                issues.append(AuditIssue("missing-host", "error", event.event_id, "successful event has no host"))
            if event.parent_event_id and event.parent_event_id not in self.lineage.events:
                issues.append(AuditIssue("missing-parent", "error", event.event_id, event.parent_event_id))
        return issues

    def public(self) -> dict[str, Any]:
        issues = [issue.public() for issue in self.issues()]
        return {
            "source_stats": self.source_stats(),
            "lineage": self.lineage_stats(),
            "required_sources": list(self.required_sources),
            "issue_count": len(issues),
            "issues": issues,
        }


class PlanAudit:
    def __init__(self, catalog: Mapping[str, Mapping[str, Any]], optimization: Mapping[str, Any], selected: Iterable[str]):
        self.catalog = catalog
        self.optimization = optimization
        self.selected = tuple(selected)
        self.policy = ActionPolicy(catalog, optimization)

    def dependency_report(self) -> list[dict[str, Any]]:
        positions = {action_id: index + 1 for index, action_id in enumerate(self.selected)}
        rows = []
        for action_id in self.selected:
            row = self.catalog.get(action_id, {})
            requirements = split_pipe(row.get("requires", ""))
            rows.append({
                "action_id": action_id,
                "sequence": positions[action_id],
                "requires": list(requirements),
                "satisfied": all(positions.get(dep, 10**9) < positions[action_id] for dep in requirements),
                "provides": row.get("provides", ""),
            })
        return rows

    def public(self) -> dict[str, Any]:
        selected = set(self.selected)
        provided = {
            str(self.catalog[action_id].get("provides", ""))
            for action_id in selected
            if action_id in self.catalog and self.catalog[action_id].get("provides")
        }
        required = {str(value) for value in self.optimization.get("required_capabilities", [])}
        return {
            "selected_count": len(self.selected),
            "total_minutes": self.policy.total_minutes(selected),
            "required_capabilities": sorted(required),
            "provided_capabilities": sorted(provided),
            "missing_capabilities": sorted(required - provided),
            "dependencies": self.dependency_report(),
            "conflicts": [
                {"action_id": action_id, "capability": capability}
                for action_id, capability in self.policy.conflicts(selected)
            ],
        }
