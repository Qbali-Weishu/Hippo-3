from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .contracts import EvidenceContract
from .domain import EvidenceWindow, split_csv, split_pipe


class ConfigurationError(ValueError):
    """Raised when the case contract cannot be loaded safely."""


@dataclass(frozen=True)
class CaseConfig:
    root: Path
    document: dict[str, Any]

    @classmethod
    def load(cls, root: Path) -> "CaseConfig":
        path = root / "case.json"
        try:
            document = json.loads(path.read_text())
        except OSError as exc:
            raise ConfigurationError(f"cannot read case configuration: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"case configuration is not JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise ConfigurationError("case configuration must be an object")
        required = {
            "case", "hosts", "identities", "indicators", "event_schema",
            "action_catalog", "optimization", "resilience", "clock_sync",
            "evidence_manifest",
        }
        missing = sorted(required - set(document))
        if missing:
            raise ConfigurationError("case configuration missing: " + ", ".join(missing))
        config = cls(root=root, document=document)
        config.validate_shape()
        return config

    @property
    def scope(self) -> dict[str, Any]:
        return self.document["case"]

    @property
    def case_id(self) -> str:
        return str(self.scope["case_id"])

    @property
    def hosts(self) -> dict[str, dict[str, Any]]:
        return {str(row["host"]): row for row in self.document["hosts"]}

    @property
    def identities(self) -> dict[str, dict[str, Any]]:
        return {str(row["principal"]): row for row in self.document["identities"]}

    @property
    def indicators(self) -> list[dict[str, Any]]:
        return list(self.document["indicators"])

    @property
    def action_catalog(self) -> dict[str, dict[str, Any]]:
        return {str(row["action_id"]): row for row in self.document["action_catalog"]}

    @property
    def clock_sync(self) -> list[dict[str, Any]]:
        return list(self.document["clock_sync"])

    @property
    def evidence_manifest(self) -> dict[str, dict[str, Any]]:
        return {str(row["filename"]): row for row in self.document["evidence_manifest"]}

    def evidence_paths(self) -> list[Path]:
        paths = [self.root / filename for filename in self.evidence_manifest]
        return sorted(paths, key=lambda path: path.name)

    @property
    def evidence_contract(self) -> EvidenceContract:
        from .clock import parse_time
        return EvidenceContract.from_document(self.document, parse_time)

    @property
    def evidence_window(self) -> EvidenceWindow:
        from .clock import parse_time
        start, end = self.scope["incident_window"]
        return EvidenceWindow(parse_time(start), parse_time(end))

    @property
    def host_zones(self) -> dict[str, str]:
        return {host: str(row.get("zone", "")) for host, row in self.hosts.items()}

    @property
    def principal_hosts(self) -> dict[str, set[str]]:
        return {
            principal: set(split_csv(row.get("allowed_hosts", "")))
            for principal, row in self.identities.items()
        }

    @property
    def network_policy(self) -> dict[tuple[str, str, str], dict[str, Any]]:
        return {
            (str(row.get("src_zone", "")), str(row.get("dst_zone", "")), str(row.get("protocol", ""))): row
            for row in self.document.get("network_paths", [])
        }

    @property
    def lineage_policy(self) -> dict[str, Any]:
        return dict(self.document.get("lineage_policy", {}))

    @property
    def arbitration(self) -> dict[str, Any]:
        return dict(self.document.get("arbitration", {}))

    def context_family(self, context: str) -> str | None:
        for family in self.lineage_policy.get("context_families", []):
            if context in set(str(item) for item in family.get("contexts", [])):
                return str(family.get("family", ""))
        return None

    def allowed_principal_transition(self, parent: str, child: str, kind: str) -> bool:
        if parent == child:
            return True
        return any(
            str(rule.get("from")) == parent
            and str(rule.get("to")) == child
            and str(rule.get("via_kind")) == kind
            for rule in self.lineage_policy.get("allowed_principal_transitions", [])
        )

    def allowed_host_transition(self, parent: str, child: str, kind: str) -> bool:
        if parent == child:
            return True
        return any(
            str(rule.get("from")) == parent
            and str(rule.get("to")) == child
            and str(rule.get("via_kind")) == kind
            for rule in self.lineage_policy.get("allowed_host_transitions", [])
        )

    def action_enabled(self, action_id: str) -> bool:
        return action_id in self.action_catalog and action_id not in set(self.document["optimization"].get("forbidden_actions", []))

    def validate_cross_references(self) -> None:
        contract = self.evidence_contract
        contract.validate()
        known_candidates = {str(row["candidate_id"]) for row in self.indicators}
        for row in self.indicators:
            contract.validate_indicator(row)
            predecessor = str(row.get("predecessor", ""))
            if predecessor and predecessor not in known_candidates:
                raise ConfigurationError(f"indicator references unknown predecessor {predecessor}")
            if str(row.get("branch", "")).strip() == "":
                raise ConfigurationError(f"indicator {row['candidate_id']} has no branch")
            if int(row.get("max_gap_seconds", 0)) <= 0:
                raise ConfigurationError(f"indicator {row['candidate_id']} has invalid max gap")
        action_ids = self.all_action_ids()
        required = self.required_action_ids()
        forbidden = set(self.document["optimization"].get("forbidden_actions", []))
        if not required.issubset(action_ids):
            raise ConfigurationError("required action is absent from action catalog")
        if required & forbidden:
            raise ConfigurationError("required action is forbidden")
        for action_id, row in self.action_catalog.items():
            if int(row.get("minutes", 0)) <= 0:
                raise ConfigurationError(f"action {action_id} has invalid duration")
            for dependency in split_pipe(row.get("requires", "")):
                if dependency not in action_ids:
                    raise ConfigurationError(f"action {action_id} references unknown prerequisite {dependency}")
        for before, after in self.document["optimization"].get("ordering", []):
            if before not in action_ids or after not in action_ids:
                raise ConfigurationError("optimization ordering references unknown action")
        if not self.lineage_policy.get("allowed_principal_transitions"):
            raise ConfigurationError("lineage policy has no principal transitions")
        if not self.arbitration.get("score_dimensions"):
            raise ConfigurationError("arbitration policy has no score dimensions")

    def validate_shape(self) -> None:
        if not self.case_id:
            raise ConfigurationError("case_id must not be empty")
        if len(self.scope.get("incident_window", [])) != 2:
            raise ConfigurationError("incident_window must contain a start and end")
        if not self.hosts or not self.identities:
            raise ConfigurationError("host and identity inventories must not be empty")
        if not self.indicators or not self.action_catalog:
            raise ConfigurationError("indicator and action catalogs must not be empty")
        try:
            self.evidence_contract.window.validate()
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(f"invalid incident window: {exc}") from exc
        for filename, entry in self.evidence_manifest.items():
            if not filename.startswith("evidence/") or not filename.endswith(".jsonl"):
                raise ConfigurationError(f"invalid evidence manifest path: {filename}")
            if int(entry["record_count"]) < 1:
                raise ConfigurationError(f"empty evidence source: {filename}")
        self.validate_cross_references()

    def authorized_host(self, host: str) -> bool:
        return host in set(self.scope.get("authorized_hosts", [])) and host in self.hosts

    def principal_allowed_on(self, principal: str, host: str) -> bool:
        identity = self.identities.get(principal)
        if not identity or not self.authorized_host(host):
            return False
        return host in self.principal_hosts.get(principal, set())

    def required_sources(self, indicator: dict[str, Any]) -> set[str]:
        return set(str(indicator["required_sources"]).split("|"))

    def validate_manifest_counts(self, counts: dict[str, int]) -> None:
        try:
            self.evidence_contract.validate_counts(counts)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc

    def all_action_ids(self) -> set[str]:
        return set(self.action_catalog)

    def required_action_ids(self) -> set[str]:
        return set(self.document["optimization"]["required_actions"])

    def iter_dependency_edges(self) -> Iterable[tuple[str, str]]:
        for action_id, row in self.action_catalog.items():
            for dependency in filter(None, str(row.get("requires", "")).split("|")):
                yield dependency, action_id
        yield from (tuple(edge) for edge in self.document["optimization"]["ordering"])
