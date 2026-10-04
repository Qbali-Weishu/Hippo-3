from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import EvidenceAudit, PlanAudit
from .config import CaseConfig
from .extraction import extract
from .graph import correlate
from .impact import quantify
from .ingest import load_events
from .plan import ActionPlanner, validate_plan
from .serialization import atomic_output_dir, write_json


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forensicctl")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("analyze", "extract"):
        command = sub.add_parser(name)
        command.add_argument("--input", required=True, type=Path)
        command.add_argument("--output", required=True, type=Path)
    plan = sub.add_parser("validate-plan")
    plan.add_argument("--input", required=True, type=Path)
    plan.add_argument("--plan", required=True, type=Path)
    return parser


def _check_paths(input_dir: Path, output_dir: Path) -> None:
    input_dir = input_dir.resolve()
    output_dir = output_dir.resolve()
    if input_dir == output_dir or input_dir in output_dir.parents:
        raise ValueError("output directory must be separate from input evidence")
    if output_dir in input_dir.parents:
        raise ValueError("output directory cannot contain the input evidence")


def _analyze(config: CaseConfig, output_dir: Path) -> None:
    events, clocks, counts = load_events(config)
    matrix, chain = correlate(config, events)
    impact = quantify(events, chain)
    analysis = {
        "case_id": config.case_id,
        "clock_models": clocks.public(),
        "evidence": {"event_count": len(events), "shard_count": len(counts), "shard_counts": counts},
        "candidate_matrix": matrix,
        "selected_chain": chain,
        "evidence_audit": EvidenceAudit(events, config.evidence_contract.source_names).public(),
    }
    plan = ActionPlanner(config).build()
    plan["policy_audit"] = PlanAudit(config.action_catalog, config.document["optimization"], [item["action_id"] for item in plan["selected_actions"]]).public()
    errors = validate_plan_document(config, plan)
    if errors:
        raise ValueError("generated plan is invalid: " + "; ".join(errors))
    with atomic_output_dir(output_dir) as staging:
        write_json(staging / "analysis.json", analysis)
        write_json(staging / "impact.json", impact)
        write_json(staging / "containment_plan.json", plan)


def validate_plan_document(config: CaseConfig, plan: dict[str, object]) -> list[str]:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="forensicctl-plan-") as directory:
        path = Path(directory) / "plan.json"
        path.write_text(json.dumps(plan))
        return validate_plan(config, path)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in ("analyze", "extract"):
            _check_paths(args.input, args.output)
            config = CaseConfig.load(args.input)
            if args.command == "extract":
                extract(config, args.output)
            else:
                _analyze(config, args.output)
            return 0
        config = CaseConfig.load(args.input)
        errors = validate_plan(config, args.plan)
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print("plan valid")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"forensicctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
