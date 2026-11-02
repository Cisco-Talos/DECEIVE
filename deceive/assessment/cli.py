from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from deceive.assessment.models import Decisions, ProbeAction, Review
from deceive.assessment.workspace import load_json, prepare, write_json


def add_parser(commands) -> None:
    assess = commands.add_parser("assess", help="Development assessment lifecycle and active probes")
    actions = assess.add_subparsers(dest="assessment_action", required=True)
    start = actions.add_parser("prepare")
    start.add_argument("--spec", type=Path, required=True)
    start.add_argument("--results-dir", type=Path, required=True)
    start.add_argument("--root", type=Path, default=Path.cwd())
    for name in ("begin-loop", "probe", "record-review", "end-loop", "status", "resume", "finish", "render", "cleanup"):
        action = actions.add_parser(name)
        action.add_argument("--run", type=Path, required=True)
        if name == "begin-loop":
            action.add_argument("--retry", action="store_true")
        if name == "resume":
            action.add_argument("--additional-loops", type=int, default=0)
        if name == "probe":
            action.add_argument("--role", choices=["protocol", "product", "attacker", "consistency"], required=True)
            action.add_argument("--target", required=True)
            action.add_argument("--action", required=True, help="JSON object, or @path to JSON")
        if name == "record-review":
            action.add_argument("--file", type=Path, required=True)
        if name == "end-loop":
            action.add_argument("--decisions", type=Path)
            action.add_argument("--confirm-plateau", action="store_true")
        if name in {"finish", "cleanup"}:
            action.add_argument("--remove", action="store_true")
            action.add_argument("--reason", choices=["cancelled", "budget_exhausted", "blocked", "incomplete"])
            action.add_argument("--note", help="Diagnosis/evidence required for a manually declared blocker")


def run(args: argparse.Namespace) -> int:
    from deceive.assessment import engine
    action = args.assessment_action
    if action == "prepare":
        state = prepare(args.spec.resolve(), args.results_dir.resolve(), args.root.resolve())
        result = engine.public_state(state) | {"run": str(args.results_dir.resolve())}
    else:
        directory = args.run.resolve()
        if action == "begin-loop":
            result = asyncio.run(engine.begin_loop(directory, retry=args.retry))
        elif action == "probe":
            state = load_json(directory / "state.json")
            if state["phase"] != "active":
                raise ValueError("Start or resume an active loop before probing")
            engine.check_fresh(state)
            value = json.loads(Path(args.action[1:]).read_text() if args.action.startswith("@") else args.action)
            probe = ProbeAction.model_validate(value)
            result = asyncio.run(engine.rpc(directory, {"role": args.role, "target": args.target,
                                                        "action": probe.model_dump(mode="json")}))
        elif action == "record-review":
            result = engine.record_review(directory, Review.model_validate(load_json(args.file)))
        elif action == "end-loop":
            decisions = Decisions.model_validate(load_json(args.decisions)) if args.decisions else Decisions()
            result = asyncio.run(engine.end_loop(directory, decisions, plateau_confirmed=args.confirm_plateau))
        elif action == "status":
            result = engine.public_state(load_json(directory / "state.json"))
        elif action == "resume":
            result = asyncio.run(engine.resume(directory, additional_loops=args.additional_loops))
        elif action == "render":
            from deceive.assessment.dashboard import render
            result = {"dashboard": str(render(directory))}
        else:
            if args.reason == "blocked" and not args.note:
                raise ValueError("A blocker needs --note with attempted diagnoses and required input")
            if args.note:
                write_json(directory / "final-note.json", {"reason": args.reason, "note": args.note})
            result = asyncio.run(engine.finish(directory, remove=args.remove, reason=args.reason))
    print(json.dumps(result, indent=2))
    if action == "finish":
        return 0 if result["qualified"] and not result["teardown_errors"] else 1
    return 0
