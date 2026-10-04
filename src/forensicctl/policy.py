from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .domain import DependencyState, split_pipe


@dataclass(frozen=True)
class PolicyViolation:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


class ActionPolicy:
    def __init__(self, catalog: Mapping[str, Mapping[str, Any]], optimization: Mapping[str, Any]):
        self.catalog = catalog
        self.optimization = optimization

    def ids(self, plan: Iterable[Mapping[str, Any]]) -> list[str]:
        return [str(item.get("action_id", "")) for item in plan]

    def required_ids(self) -> set[str]:
        return {str(item) for item in self.optimization.get("required_actions", [])}

    def forbidden_ids(self) -> set[str]:
        return {str(item) for item in self.optimization.get("forbidden_actions", [])}

    def dependency_edges(self, selected: Iterable[str], include_ordering: bool = True) -> dict[str, set[str]]:
        chosen = set(selected)
        edges = {action_id: set() for action_id in chosen}
        for action_id in chosen:
            row = self.catalog.get(action_id, {})
            edges[action_id].update(dep for dep in split_pipe(row.get("requires", "")) if dep in chosen)
        if include_ordering:
            for before, after in self.optimization.get("ordering", []):
                if before in chosen and after in chosen:
                    edges[after].add(before)
        return edges

    def topological_order(self, selected: Iterable[str]) -> list[str]:
        chosen = set(selected)
        state = DependencyState(self.catalog, tuple(chosen))
        graph = self.dependency_edges(chosen)
        result: list[str] = []
        while graph:
            ready = sorted(action_id for action_id, deps in graph.items() if not deps)
            if not ready:
                raise ValueError("action constraints contain a cycle")
            result.extend(ready)
            for action_id in ready:
                graph.pop(action_id)
            for deps in graph.values():
                deps.difference_update(ready)
        if set(result) != chosen:
            raise ValueError("action topological order is incomplete")
        return result

    def conflicts(self, selected: Iterable[str]) -> list[tuple[str, str]]:
        chosen = set(selected)
        capabilities = {
            str(self.catalog[action_id].get("provides", ""))
            for action_id in chosen
            if action_id in self.catalog and self.catalog[action_id].get("provides")
        }
        found: list[tuple[str, str]] = []
        for action_id in sorted(chosen):
            for conflict in split_pipe(self.catalog.get(action_id, {}).get("conflicts", "")):
                if conflict in capabilities:
                    found.append((action_id, conflict))
        return found

    def violations(self, plan: list[dict[str, Any]]) -> list[PolicyViolation]:
        ids = self.ids(plan)
        selected = set(ids)
        violations: list[PolicyViolation] = []
        forbidden = selected & self.forbidden_ids()
        if forbidden:
            violations.append(PolicyViolation("forbidden-action", ",".join(sorted(forbidden))))
        if selected != self.required_ids():
            violations.append(PolicyViolation("action-set", "required action set does not match"))
        positions = {action_id: index for index, action_id in enumerate(ids)}
        for action_id, dependencies in self.dependency_edges(selected).items():
            for dependency in dependencies:
                if positions.get(dependency, len(ids)) >= positions.get(action_id, -1):
                    violations.append(PolicyViolation("prerequisite", f"{dependency} must precede {action_id}"))
        for action_id, capability in self.conflicts(selected):
            violations.append(PolicyViolation("conflict", f"{action_id} conflicts with {capability}"))
        required_caps = {str(item) for item in self.optimization.get("required_capabilities", [])}
        provided = {
            str(self.catalog[action_id].get("provides", ""))
            for action_id in selected
            if action_id in self.catalog and self.catalog[action_id].get("provides")
        }
        if not required_caps.issubset(provided):
            violations.append(PolicyViolation("capability", "required capabilities are incomplete"))
        return violations

    def total_minutes(self, selected: Iterable[str]) -> int:
        return sum(int(self.catalog[action_id]["minutes"]) for action_id in selected)
