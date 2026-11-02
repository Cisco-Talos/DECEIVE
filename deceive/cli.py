from __future__ import annotations

import argparse
import asyncio
import json
import io
from importlib.metadata import version
import os
from pathlib import Path
import signal
import sys
import time

from pydantic import ValidationError

from deceive.behaviors import BUILTIN_BEHAVIORS, validate_behavior
from deceive.config import load_deployment, load_profile
from deceive.composition import resolve
from deceive.migrate import migrate
from deceive.models import Deception, Deployment, ProviderConfig
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def selection_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("--config", "-c", type=Path)
    command.add_argument("--profile", "--deception", dest="profile", action="append",
                         help="Add a built-in name or profile YAML (repeatable; additive with --config)")
    command.add_argument("--data-dir", type=Path)
    command.add_argument("--host")
    command.add_argument("--port", type=int)
    command.add_argument("--https", action="store_true")
    command.add_argument("--http-versions", nargs="+", choices=["1.1", "2", "3"])
    command.add_argument("--quic-port", type=int)
    command.add_argument("--advertised-port", type=int)
    command.add_argument("--provider", choices=["openai", "azure", "bedrock", "ollama", "gemini"])
    command.add_argument("--model")
    command.add_argument("--analyze", action="store_true")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Profile-driven network deception")
    result.add_argument("--version", action="version", version="%(prog)s " + version("deceive"))
    commands = result.add_subparsers(dest="command", required=True)
    from deceive.assessment.cli import add_parser
    add_parser(commands)
    serve = commands.add_parser("serve", help="Start protocol listeners")
    selection_arguments(serve)
    profiles = commands.add_parser("profile", help="Validate and evaluate profiles")
    actions = profiles.add_subparsers(dest="action", required=True)
    validate = actions.add_parser("validate")
    validate.add_argument("profile")
    evaluate = actions.add_parser("evaluate")
    evaluate.add_argument("profile")
    evaluate.add_argument("--suite", required=True, type=Path)
    evaluate.add_argument("--report-dir", required=True, type=Path)
    evaluate.add_argument("--config", type=Path, help="Provider configuration for explicit live-model runs")
    evaluate.add_argument("--live-model", action="store_true")
    configs = commands.add_parser("config")
    config_actions = configs.add_subparsers(dest="action", required=True)
    check = config_actions.add_parser("validate", help="Validate selections and print the listener plan without starting")
    selection_arguments(check)
    migration = config_actions.add_parser("migrate")
    migration.add_argument("source", type=Path)
    migration.add_argument("--output-dir", required=True, type=Path)
    health = commands.add_parser("healthcheck")
    health.add_argument("--data-dir", type=Path, default=Path(os.environ.get("DECEIVE_DATA_DIR", ".deceive")))
    return result


def deployment_from_args(args: argparse.Namespace) -> Deployment:
    if args.config:
        if any((args.provider, args.model, args.host, args.port is not None,
                args.https, args.http_versions, args.quic_port is not None, args.advertised_port, args.analyze)):
            raise ValueError("Use deployment YAML for listener settings when --config is supplied")
        deployment = load_deployment(args.config, additional_profiles=args.profile)
        if args.data_dir:
            deployment.data_dir = args.data_dir.resolve()
        return deployment
    providers = {}
    if args.provider:
        if not args.model:
            raise ValueError("--provider requires --model")
        providers["default"] = ProviderConfig(kind=args.provider, model=args.model)
    elif args.model:
        raise ValueError("--model requires --provider")
    deployment = Deployment(
        data_dir=(args.data_dir or Path(os.environ.get("DECEIVE_DATA_DIR", ".deceive"))).resolve(),
        providers=providers, deceptions=[Deception(profile=ref) for ref in args.profile or ["demo-http"]],
        deception_defaults={"host": args.host or "0.0.0.0",
                            "provider": "default" if providers else None, "analyze": args.analyze})
    plan = resolve(deployment)
    if len(plan.listeners) == 1:
        # Preserve key/certificate filenames for the existing single-profile CLI.
        plan.listeners[0].name = "main"
    for listener in plan.listeners:
        if args.https and listener.protocol == "http":
            listener.protocol = "https"
            if args.port is None:
                listener.port = 8443
        if args.port is not None:
            listener.port = args.port
        if args.http_versions:
            listener.versions = args.http_versions
        if args.quic_port is not None:
            listener.quic_port = args.quic_port
        if args.advertised_port is not None:
            listener.advertised_port = args.advertised_port
    # Materialize CLI transport overrides, then let Runtime resolve profiles afresh.
    return Deployment.model_validate(deployment.model_dump() | {
        "listeners": [l.model_dump() for l in plan.listeners], "deceptions": []})


async def serve(deployment: Deployment) -> None:
    runtime = Runtime(deployment)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        await runtime.start()
        await stop.wait()
    finally:
        await runtime.close()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)


async def validate_config(deployment: Deployment) -> None:
    runtime = Runtime(deployment, telemetry=Telemetry(deployment.sensor_name, stream=io.StringIO()))
    try:
        print("Valid runtime configuration:")
        for line in runtime.plan.describe():
            print("  " + line)
        print("No listeners started; provider connectivity and port availability are checked at startup.")
    finally:
        await runtime.close()


def healthcheck(data_dir: Path) -> bool:
    try:
        status = json.loads((data_dir / "status.json").read_text())
        if not status["ready"] or not status["listeners"] or time.time() - status["updated"] > 5:
            return False
        os.kill(status["pid"], 0)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "assess":
            from deceive.assessment.cli import run
            return run(args)
        elif args.command == "serve":
            asyncio.run(serve(deployment_from_args(args)))
        elif args.command == "healthcheck":
            return 0 if healthcheck(args.data_dir) else 1
        elif args.command == "config":
            if args.action == "validate":
                asyncio.run(validate_config(deployment_from_args(args)))
            else:
                for note in migrate(args.source, args.output_dir):
                    print(note)
        elif args.action == "validate":
            profile = load_profile(args.profile)
            for behavior in profile.behaviors:
                if behavior.kind not in BUILTIN_BEHAVIORS:
                    raise ValueError(f"Unsupported behavior capability: {behavior.kind}")
                validate_behavior(behavior, profile)
            print(f"Valid: {profile.id} version {profile.version}")
        else:
            from deceive.evaluate import evaluate

            report = asyncio.run(evaluate(args.profile, args.suite, args.report_dir,
                                         config_path=args.config, live_model=args.live_model))
            print(f"{'PASS' if report['passed'] else 'FAIL'}: {report['passed_cases']}/{report['total_cases']} cases")
            return 0 if report["passed"] else 1
        return 0
    except ValidationError as exc:
        # Default Pydantic formatting includes input values, possibly secrets.
        print("Invalid configuration: " + "; ".join(
            ".".join(map(str, error["loc"])) + ": " + error["msg"]
            for error in exc.errors(include_input=False)
        ), file=sys.stderr)
    except (ValueError, OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
    except Exception as exc:
        # Intentional process boundary: SDK initialization errors may carry secrets.
        print(f"Startup failed ({type(exc).__name__}); check provider credentials/configuration", file=sys.stderr)
    return 2
