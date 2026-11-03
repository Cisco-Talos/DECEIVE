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
from deceive.config import fingerprint, load_deployment, load_profile
from deceive.composition import resolve
from deceive.migrate import migrate
from deceive.models import Deception, Deployment, ProviderConfig
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry
from deceive.operations import OperationResult, output_argument


def selection_arguments(command: argparse.ArgumentParser) -> None:
    output_argument(command)
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
    output_argument(result)
    result.add_argument("--version", action="version", version="%(prog)s " + version("deceive"))
    commands = result.add_subparsers(dest="command", required=True)
    from deceive.assessment.cli import add_parser
    add_parser(commands)
    serve = commands.add_parser("serve", help="Start protocol listeners")
    selection_arguments(serve)
    profiles = commands.add_parser("profile", help="Validate and evaluate profiles")
    output_argument(profiles)
    actions = profiles.add_subparsers(dest="action", required=True)
    listing = actions.add_parser("list", help="Discover bundled and local profiles")
    output_argument(listing)
    listing.add_argument("--directory", type=Path, action="append", default=[])
    listing.add_argument("--protocol", choices=["ssh", "http", "https"])
    listing.add_argument("--vulnerabilities", action="store_true")
    show = actions.add_parser("show", help="Inspect a profile and its resolved baseline")
    output_argument(show)
    show.add_argument("profile")
    show.add_argument("--directory", type=Path, action="append", default=[])
    validate = actions.add_parser("validate")
    output_argument(validate)
    validate.add_argument("profile")
    evaluate = actions.add_parser("evaluate")
    output_argument(evaluate)
    evaluate.add_argument("profile")
    evaluate.add_argument("--suite", required=True, type=Path)
    evaluate.add_argument("--report-dir", required=True, type=Path)
    evaluate.add_argument("--config", type=Path, help="Provider configuration for explicit live-model runs")
    evaluate.add_argument("--live-model", action="store_true")
    configs = commands.add_parser("config")
    output_argument(configs)
    config_actions = configs.add_subparsers(dest="action", required=True)
    check = config_actions.add_parser("validate", help="Validate selections and print the listener plan without starting")
    selection_arguments(check)
    migration = config_actions.add_parser("migrate")
    output_argument(migration)
    migration.add_argument("source", type=Path)
    migration.add_argument("--output-dir", required=True, type=Path)
    health = commands.add_parser("healthcheck")
    output_argument(health)
    health.add_argument("--data-dir", type=Path, default=Path(os.environ.get("DECEIVE_DATA_DIR", ".deceive")))
    managed = commands.add_parser("deployment", help="Manage named Docker deployments")
    output_argument(managed)
    managed_actions = managed.add_subparsers(dest="action", required=True)
    for name in ("start", "stop", "list", "status", "remove"):
        action = managed_actions.add_parser(name)
        if name == "start":
            selection_arguments(action)
            action.add_argument("--image", help="Already installed standard image (new deployments: deceive:local)")
            action.add_argument("--publish-host", default="127.0.0.1")
            action.add_argument("--publish", action="append", default=[], metavar="LISTENER=PORT")
            action.add_argument("--env", dest="env_names", action="append", default=[], metavar="NAME")
            action.add_argument("--aws-dir", type=Path)
            action.add_argument("--timeout", type=float, default=30)
        else:
            output_argument(action)
        action.add_argument("--state-dir", type=Path,
                            default=Path(os.environ.get("DECEIVE_STATE_DIR", ".deceive/managed")))
        if name != "list":
            action.add_argument("name")
        if name == "stop":
            action.add_argument("--timeout", type=int, default=30)
        if name == "remove":
            action.add_argument("--remove-data", action="store_true")
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


async def validated_plan(deployment: Deployment) -> dict:
    runtime = Runtime(deployment, telemetry=Telemetry(deployment.sensor_name, stream=io.StringIO()))
    try:
        return {"description": runtime.plan.describe(), "listeners": [{
            "name": listener.name, "protocol": listener.protocol, "host": listener.host,
            "port": listener.port, "quic_port": listener.quic_port,
            "versions": listener.versions if listener.protocol in {"http", "https"} else [],
            "profiles": [{"id": p.id, "version": p.version, "fingerprint": fingerprint(p)}
                         for p in runtime.plan.members[listener.name]],
        } for listener in runtime.plan.listeners]}
    finally:
        await runtime.close()


async def validate_config(deployment: Deployment) -> None:
    plan = await validated_plan(deployment)
    print("Valid runtime configuration:")
    for line in plan["description"]:
        print("  " + line)
    print("No listeners started; provider connectivity and port availability are checked at startup.")


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
    argv = list(sys.argv[1:] if argv is None else argv)
    json_output = "--json" in argv
    operation = "cli.parse"
    try:
        try:
            args = parser().parse_args(argv)
            json_output = getattr(args, "json_output", False)
        except SystemExit as exc:
            if json_output and exc.code:
                return OperationResult(operation, exit_code=2, error={
                    "code": "invalid_arguments", "message": "Invalid arguments; consult command --help"}).emit(
                        json_output=True, lines=[])
            raise
        operation = args.command + ("." + args.assessment_action if args.command == "assess"
                                   else "." + args.action if hasattr(args, "action") else "")
        outcome = OperationResult(operation)
        lines = []
        if args.command == "assess":
            from deceive.assessment.cli import execute
            outcome.data, outcome.exit_code = execute(args)
            # Preserve existing assessment JSON unless the common envelope is requested.
            if not json_output:
                print(json.dumps(outcome.data, indent=2))
                return outcome.exit_code
            outcome.artifacts = [outcome.data[key] for key in ("dashboard",) if key in outcome.data]
        elif args.command == "serve":
            if json_output:
                raise ValueError("serve streams JSONL telemetry; use deployment start --json for an operation result")
            asyncio.run(serve(deployment_from_args(args)))
        elif args.command == "healthcheck":
            ready = healthcheck(args.data_dir)
            outcome.data, outcome.exit_code = {"ready": ready}, 0 if ready else 1
        elif args.command == "deployment":
            from deceive.managed import DeploymentManager
            manager = DeploymentManager(args.state_dir)
            if args.action == "start":
                if args.data_dir:
                    raise ValueError("Managed deployments use a persistent Docker volume; --state-dir selects manager metadata, while serve supports --data-dir")
                if args.host and args.publish_host != "127.0.0.1" and args.host != args.publish_host:
                    raise ValueError("--host and --publish-host must agree")
                settings = any((args.config, args.profile, args.provider, args.model, args.host,
                    args.port is not None, args.https, args.http_versions, args.quic_port is not None,
                    args.advertised_port, args.analyze, args.data_dir))
                retained = (manager.directory(args.name) / "record.json").exists()
                config = deployment_from_args(args) if settings or not retained else None
                outcome.data = asyncio.run(manager.start(args.name, config, image=args.image,
                    publish_host=args.host or args.publish_host, publish=args.publish, env_names=args.env_names,
                    aws_dir=args.aws_dir, timeout=args.timeout))
            elif args.action == "stop":
                outcome.data = manager.stop(args.name, timeout=args.timeout)
            elif args.action == "status":
                outcome.data = manager.status(args.name)
            elif args.action == "list":
                outcome.data = {"deployments": manager.list()}
            else:
                outcome.data = manager.remove(args.name, remove_data=args.remove_data)
            if args.action == "list":
                lines = [f'{row["name"]}: {row["state"]} ready={row["ready"]}'
                         for row in outcome.data["deployments"]] or ["No managed deployments"]
            elif args.action == "remove":
                lines = [f'{args.name}: removed; data {"retained" if outcome.data["data_retained"] else "removed"}']
            else:
                lines = [f'{args.name}: {outcome.data["state"]} ready={outcome.data["ready"]}',
                         f'Data volume: {outcome.data["volume"]}']
                for listener in outcome.data["listeners"]:
                    lines.extend(f'{listener["name"]}: {listener["protocol"].upper()} '
                                 f'{listener["host"]}:{binding["host_port"]}/{binding["transport"]}'
                                 for binding in listener["bindings"])
        elif args.command == "config":
            if args.action == "validate":
                outcome.data = asyncio.run(validated_plan(deployment_from_args(args)))
                lines = ["Valid runtime configuration:"] + ["  " + row for row in outcome.data["description"]]
                lines.append("No listeners started; provider connectivity and port availability are checked at startup.")
            else:
                lines = list(migrate(args.source, args.output_dir))
                outcome.data = {"notes": lines, "output_dir": str(args.output_dir.resolve())}
                outcome.artifacts = [str(path.resolve()) for path in sorted(args.output_dir.iterdir()) if path.is_file()]
        elif args.action == "list":
            from deceive.catalog import profiles
            rows = profiles(args.directory)
            rows = [row for row in rows if (not args.protocol or row["protocol"] == args.protocol)
                    and (not args.vulnerabilities or row["vulnerability"])]
            outcome.data = {"profiles": rows}
            lines = [f'{row["id"]}@{row["version"]} {row["protocol"].upper()} {row["description"]}'
                     for row in rows] or ["No matching profiles"]
        elif args.action == "show":
            from deceive.catalog import show
            outcome.data = show(args.profile, args.directory)
            lines = [f'{outcome.data["id"]}@{outcome.data["version"]}: {outcome.data["description"]}',
                     f'Protocol: {outcome.data["protocol"]}; fallback: {outcome.data["fallback"]}',
                     "Identity: " + json.dumps(outcome.data["effective_identity"]),
                     "Requirements: " + json.dumps(outcome.data["definition"].get("requirements", {}))]
            lines.extend("Limitation: " + value for value in outcome.data["limitations"])
        elif args.action == "validate":
            profile = load_profile(args.profile)
            from deceive.composition import _compose
            effective, _ = _compose([profile])
            for behavior in effective.behaviors:
                if behavior.kind not in BUILTIN_BEHAVIORS:
                    raise ValueError(f"Unsupported behavior capability: {behavior.kind}")
                validate_behavior(behavior, effective)
            outcome.data = {"id": profile.id, "version": profile.version, "fingerprint": fingerprint(profile)}
            lines = [f"Valid: {profile.id} version {profile.version}"]
        else:
            from deceive.evaluate import evaluate

            report = asyncio.run(evaluate(args.profile, args.suite, args.report_dir,
                                         config_path=args.config, live_model=args.live_model))
            outcome.data = {key: value for key, value in report.items() if key != "cases"}
            outcome.exit_code = 0 if report["passed"] else 1
            outcome.artifacts = [str(path.resolve()) for path in sorted(args.report_dir.iterdir()) if path.is_file()]
            lines = [f"{'PASS' if report['passed'] else 'FAIL'}: {report['passed_cases']}/{report['total_cases']} cases"]
        return outcome.emit(json_output=json_output, lines=lines)
    except ValidationError as exc:
        # Default Pydantic formatting includes input values, possibly secrets.
        message = "Invalid configuration: " + "; ".join(
            ".".join(map(str, error["loc"])) + ": " + error["msg"]
            for error in exc.errors(include_input=False)
        )
    except (ValueError, OSError, RuntimeError) as exc:
        message = str(exc)
    except Exception as exc:
        # Intentional process boundary: SDK initialization errors may carry secrets.
        message = f"Operation failed ({type(exc).__name__}); check provider credentials/configuration"
    if json_output:
        return OperationResult(operation, exit_code=2,
                               error={"code": "operation_error", "message": message}).emit(json_output=True, lines=[])
    print(message, file=sys.stderr)
    return 2
