from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import CaseConfig
from .domain import split_pipe


@dataclass(frozen=True)
class PlanError:
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.code}: {self.detail}"


@dataclass(frozen=True)
class Action:
    action_id: str
    row: dict[str, Any]
    dependencies: frozenset[str]
    capabilities: frozenset[str]
    conflicts: frozenset[str]
    minutes: int


class ActionPolicy:
    def __init__(self, catalog: dict[str, dict[str, Any]], optimization: dict[str, Any]):
        self.catalog = catalog
        self.optimization = optimization
        self.actions = {
            action_id: Action(
                action_id=action_id,
                row=row,
                dependencies=frozenset(split_pipe(row.get("requires", ""))),
                capabilities=frozenset(filter(None, [str(row.get("provides", ""))])),
                conflicts=frozenset(split_pipe(row.get("conflicts", ""))),
                minutes=int(row.get("minutes", 0)),
            )
            for action_id, row in catalog.items()
        }

    def required_ids(self) -> set[str]:
        return set(map(str, self.optimization.get("required_actions", [])))

    def forbidden_ids(self) -> set[str]:
        return set(map(str, self.optimization.get("forbidden_actions", [])))

    def total_minutes(self, ids: Iterable[str]) -> int:
        return sum(self.actions[action_id].minutes for action_id in ids if action_id in self.actions)

    def dependency_closure(self, ids: Iterable[str]) -> set[str]:
        result = set(ids)
        pending = list(result)
        while pending:
            action_id = pending.pop()
            action = self.actions.get(action_id)
            if action is None:
                continue
            for dependency in action.dependencies:
                if dependency not in result:
                    result.add(dependency)
                    pending.append(dependency)
        return result

    def capabilities(self, ids: Iterable[str]) -> set[str]:
        return {capability for action_id in ids if action_id in self.actions for capability in self.actions[action_id].capabilities}

    def conflicts(self, ids: Iterable[str]) -> list[tuple[str, str]]:
        chosen = set(ids)
        result: set[tuple[str, str]] = set()
        for action_id in chosen:
            action = self.actions.get(action_id)
            if not action:
                continue
            for target in action.conflicts:
                if target in chosen:
                    result.add(tuple(sorted((action_id, target))))
                elif target in self.capabilities(chosen):
                    result.add((action_id, target))
        return sorted(result)

    def violations(self, items: list[dict[str, Any]]) -> list[PlanError]:
        ids = [str(item.get("action_id", "")) for item in items if isinstance(item, dict)]
        chosen = set(ids)
        errors: list[PlanError] = []
        positions = {action_id: index for index, action_id in enumerate(ids)}
        for action_id in chosen:
            action = self.actions.get(action_id)
            if not action:
                continue
            missing = action.dependencies - chosen
            if missing:
                errors.append(PlanError("prerequisite", f"{action_id} missing {','.join(sorted(missing))}"))
            for dependency in action.dependencies:
                if dependency in positions and positions[dependency] >= positions[action_id]:
                    errors.append(PlanError("prerequisite-order", f"{dependency} must precede {action_id}"))
        for left, right in self.conflicts(chosen):
            errors.append(PlanError("conflict", f"{left} conflicts with {right}"))
        return errors


class ActionPlanner:
    def __init__(self, config: CaseConfig):
        self.config = config
        self.catalog = config.action_catalog
        self.optimization = config.document["optimization"]
        self.policy = ActionPolicy(self.catalog, self.optimization)

    def _constraints(self) -> tuple[set[str], set[str], set[tuple[str, str]]]:
        required = self.policy.required_ids()
        forbidden = self.policy.forbidden_ids()
        ordering = {tuple(map(str, edge)) for edge in self.optimization.get("ordering", [])}
        return required, forbidden, ordering

    def _close_requirements(self, selected: set[str]) -> set[str]:
        return self.policy.dependency_closure(selected)

    def _topological_order(self, selected: set[str]) -> list[str]:
        edges = set(tuple(map(str, edge)) for edge in self.optimization.get("ordering", []))
        for action_id in selected:
            row = self.catalog[action_id]
            edges.update((dependency, action_id) for dependency in split_pipe(row.get("requires", "")))
        incoming = {action_id: set() for action_id in selected}
        outgoing: dict[str, set[str]] = defaultdict(set)
        for before, after in edges:
            if before in selected and after in selected:
                incoming[after].add(before)
                outgoing[before].add(after)
        ready = sorted(action_id for action_id, deps in incoming.items() if not deps)
        ordered: list[str] = []
        while ready:
            action_id = ready.pop(0)
            ordered.append(action_id)
            for after in sorted(outgoing[action_id]):
                incoming[after].discard(action_id)
                if not incoming[after] and after not in ordered and after not in ready:
                    ready.append(after)
                    ready.sort()
        if len(ordered) != len(selected):
            raise ValueError("action constraints contain a cycle")
        return ordered

    def _validate_selection(self, selected: set[str]) -> None:
        required, forbidden, _ = self._constraints()
        if not required.issubset(selected):
            raise ValueError("no action set satisfies the required action contract")
        if selected & forbidden:
            raise ValueError("required action closure contains a forbidden action")
        if self.policy.total_minutes(selected) > int(self.optimization.get("max_minutes", 0)):
            raise ValueError("required action closure exceeds response budget")
        capabilities = self.policy.capabilities(selected)
        missing = set(map(str, self.optimization.get("required_capabilities", []))) - capabilities
        if missing:
            raise ValueError("action set lacks capabilities: " + ", ".join(sorted(missing)))
        if self.policy.conflicts(selected):
            raise ValueError("action set violates conflicts")
        for scenario in self.config.document.get("resilience", {}).get("scenarios", []):
            if selected & set(map(str, scenario.get("unavailable", []))):
                raise ValueError(f"scenario {scenario.get('id')} has unavailable actions")
            if selected & set(map(str, scenario.get("forbidden", []))):
                raise ValueError(f"scenario {scenario.get('id')} has forbidden actions")
            if not set(map(str, scenario.get("must_preserve", []))).issubset(selected):
                raise ValueError(f"scenario {scenario.get('id')} preservation actions are missing")

    def build(self) -> dict[str, Any]:
        selected = self._close_requirements(self.policy.required_ids())
        self._validate_selection(selected)
        ordered = self._topological_order(selected)
        items = []
        for sequence, action_id in enumerate(ordered, 1):
            row = self.catalog[action_id]
            items.append({
                "action_id": action_id,
                "sequence": sequence,
                "action": str(row["action"]),
                "target": str(row["target"]),
                "minutes": int(row["minutes"]),
                "owner": _owner_for(row),
                "approval": str(row["approval"]),
                "rollback": str(row["rollback"]),
                "success_condition": str(row.get("provides", "")),
                "requires": list(split_pipe(row.get("requires", ""))),
                "provides": str(row.get("provides", "")),
            })
        return {
            "case_id": self.config.case_id,
            "selected_actions": items,
            "total_minutes": self.policy.total_minutes(selected),
            "required_capabilities": sorted(self.optimization.get("required_capabilities", [])),
            "recovery_acceptance": {
                "rpo_hours": int(self.config.document.get("recovery", {}).get("rpo_hours", 4)),
                "preserve_originals": True,
            },
            "ordering_rationale": "Dependency closure and operational precedence are topologically ordered; preservation and containment precede restoration.",
        }


def _owner_for(row: dict[str, Any]) -> str:
    return str(row.get("owner", row.get("approval", "incident_commander")))


def _validate_action_item(errors: list[PlanError], item: Any, index: int, catalog: dict[str, dict[str, Any]], positions: dict[str, int]) -> None:
    if not isinstance(item, dict):
        errors.append(PlanError("actions", f"action {index} must be an object"))
        return
    action_id = str(item.get("action_id", ""))
    row = catalog.get(action_id)
    if row is None:
        errors.append(PlanError("unknown-action", action_id))
        return
    expected = {
        "sequence": index + 1,
        "action": str(row["action"]),
        "target": str(row["target"]),
        "minutes": int(row["minutes"]),
        "owner": _owner_for(row),
        "approval": str(row["approval"]),
        "rollback": str(row["rollback"]),
        "success_condition": str(row.get("provides", "")),
        "requires": list(split_pipe(row.get("requires", ""))),
        "provides": str(row.get("provides", "")),
    }
    for field, expected_value in expected.items():
        if item.get(field) != expected_value:
            errors.append(PlanError("metadata", f"{field} mismatch for {action_id}"))
    for dependency in split_pipe(row.get("requires", "")):
        if dependency in positions and positions[dependency] >= positions.get(action_id, len(positions)):
            errors.append(PlanError("prerequisite-order", f"{dependency} must precede {action_id}"))


def validate_plan(config: CaseConfig, plan_path: Path) -> list[str]:
    errors: list[PlanError] = []
    try:
        plan = json.loads(plan_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [str(PlanError("invalid-json", str(exc)))]
    if not isinstance(plan, dict):
        return [str(PlanError("plan", "plan must be an object"))]
    if plan.get("case_id") != config.case_id:
        errors.append(PlanError("case-id", "plan case_id does not match the case configuration"))
    items = plan.get("selected_actions")
    if not isinstance(items, list):
        return [*map(str, errors), str(PlanError("actions", "selected_actions must be a list"))]
    ids = [str(item.get("action_id", "")) for item in items if isinstance(item, dict)]
    if len(ids) != len(items):
        errors.append(PlanError("actions", "each selected action must be an object"))
    if len(ids) != len(set(ids)):
        errors.append(PlanError("duplicate-action", "actions must not repeat"))
    policy = ActionPolicy(config.action_catalog, config.document["optimization"])
    chosen = set(ids)
    if chosen & policy.forbidden_ids():
        errors.append(PlanError("forbidden-action", "forbidden action selected"))
    if not policy.required_ids().issubset(chosen):
        errors.append(PlanError("action-set", "required actions are missing"))
    positions = {action_id: index for index, action_id in enumerate(ids, 1)}
    for index, item in enumerate(items):
        _validate_action_item(errors, item, index, config.action_catalog, positions)
    errors.extend(policy.violations(items))
    if policy.total_minutes(chosen) > int(config.document["optimization"]["max_minutes"]):
        errors.append(PlanError("budget", "plan exceeds time budget"))
    for before, after in config.document["optimization"].get("ordering", []):
        if before in positions and after in positions and positions[before] >= positions[after]:
            errors.append(PlanError("ordering", f"{before} must precede {after}"))
    for scenario in config.document.get("resilience", {}).get("scenarios", []):
        if chosen & set(map(str, scenario.get("unavailable", []))):
            errors.append(PlanError("scenario", f"{scenario.get('id')} uses unavailable action"))
        if chosen & set(map(str, scenario.get("forbidden", []))):
            errors.append(PlanError("scenario", f"{scenario.get('id')} uses forbidden action"))
        if not set(map(str, scenario.get("must_preserve", []))).issubset(chosen):
            errors.append(PlanError("scenario", f"{scenario.get('id')} preservation requirement missing"))
    acceptance = plan.get("recovery_acceptance")
    expected_rpo = int(config.document.get("recovery", {}).get("rpo_hours", 4))
    if not isinstance(acceptance, dict) or acceptance.get("rpo_hours") != expected_rpo or acceptance.get("preserve_originals") is not True:
        errors.append(PlanError("recovery", "RPO and original-evidence preservation are required"))
    if not isinstance(plan.get("ordering_rationale"), str) or not plan["ordering_rationale"].strip():
        errors.append(PlanError("rationale", "ordering rationale is missing"))
    return list(dict.fromkeys(str(error) for error in errors))
