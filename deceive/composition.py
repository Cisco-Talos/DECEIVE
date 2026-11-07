"""Resolve selected profiles into a conservative, reproducible listener plan."""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re

from deceive.config import fingerprint, load_profile, profile_base
from deceive.models import Behavior, CommandEnvironment, Contract, Deployment, Listener, Match, Profile, Selection


CAPABILITIES = {
    "ssh": {"ssh.commands", "ssh.structured_responses", "ssh.auth_policy", "ssh.device", "ssh.fullscreen"},
    "http": {"http.requests", "http.raw_path", "http.binary_body", "http.duplicate_headers",
             "http.sessions"},
    "https": {"http.requests", "http.raw_path", "http.binary_body", "http.duplicate_headers",
              "http.sessions"},
}


@dataclass
class Plan:
    listeners: list[Listener] = field(default_factory=list)
    profiles: dict[str, Profile] = field(default_factory=dict)
    members: dict[str, list[Profile]] = field(default_factory=dict)
    owners: dict[str, dict[str, Profile]] = field(default_factory=dict)
    bases: dict[str, Profile] = field(default_factory=dict)
    references: dict = field(default_factory=dict)

    def describe(self) -> list[str]:
        lines = []
        for listener in self.listeners:
            versions = ",".join(listener.versions) if listener.protocol in {"http", "https"} else ""
            endpoint = f"{listener.protocol.upper()} {listener.host}:{listener.port}"
            if versions:
                endpoint += f" versions={versions}"
            if "3" in listener.versions and listener.protocol == "https":
                endpoint += f" UDP={listener.quic_port if listener.quic_port is not None else listener.port}"
            names = ", ".join(f"{instance_key(p)}@{p.version}" for p in self.members[listener.name])
            if listener.name in self.bases:
                base = self.bases[listener.name]
                endpoint += f" base={base.id}@{base.version}"
            lines.append(f"{listener.name}: {endpoint} profiles=[{names}]")
        return lines


def instance_key(profile: Profile) -> str:
    return profile.instance_id or profile.id


def content_fingerprint(profile: Profile) -> str:
    raw = profile.model_dump(mode="json")
    for key in ("instance_id", "organization_id", "resolved_parameters", "parameter_origins", "binding_fingerprint", 'definition_fingerprint'):
        raw.pop(key, None)
    return fingerprint(raw)


def _transport(profile: Profile) -> str:
    return profile.requirements.protocol if profile.requirements else profile.protocol


def _port(profile: Profile) -> int:
    req = profile.requirements
    return ((req.required_port or req.preferred_port) if req else None) or {
        "ssh": 8022, "http": 8080, "https": 8443,
    }.get(_transport(profile), 8080)


def _disjoint(a: Match, b: Match) -> bool:
    # Duplicate HTTP headers can contain both values. Regex/body/state predicates
    # are deliberately not treated as proof of disjoint routing.
    if ((a.path is not None or a.method is not None) and (b.command is not None or b.command_regex is not None)
        or (b.path is not None or b.method is not None) and (a.command is not None or a.command_regex is not None)):
        return True
    if any(getattr(a, key) is not None and getattr(b, key) is not None
           and getattr(a, key) != getattr(b, key) for key in ('method', 'command')):
        return True
    if a.path is not None and b.path is not None:
        first, second = a.path.split('/'), b.path.split('/')
        return len(first) != len(second) or any(
            x != y and '{' not in x and '{' not in y for x, y in zip(first, second))
    return False


def _routed(match: Match) -> bool:
    return any((match.command is not None, match.command_regex is not None,
                match.path is not None, match.method is not None, bool(match.headers),
                match.body_contains is not None))


def merge_environment(base: CommandEnvironment | None, addition: CommandEnvironment,
                      owner: str) -> CommandEnvironment:
    if base is None:
        return addition.model_copy(deep=True)
    result = base.model_copy(deep=True)
    for field in ('dialect', 'username', 'home', 'shell_version', 'ansi_encoding'):
        if field in addition.model_fields_set and getattr(base, field) != getattr(addition, field):
            raise ValueError(f'Profile {owner} conflicts with command_environment.{field}')
    for key, value in addition.environment.items():
        same = next((k for k in result.environment if (k.casefold() if base.dialect != 'linux' else k)
                     == (key.casefold() if base.dialect != 'linux' else key)), None)
        if same is not None and result.environment[same] != value:
            raise ValueError(f'Profile {owner} conflicts with environment variable {key}')
        result.environment[same or key] = value
    for program in addition.programs:
        existing = next((p for p in result.programs if
            (p.name.casefold() if base.dialect != 'linux' else p.name) ==
            (program.name.casefold() if base.dialect != 'linux' else program.name)), None)
        if existing and existing != program:
            raise ValueError(f'Profile {owner} has conflicting command ownership: {program.name}')
        if existing is None:
            result.programs.append(program.model_copy(deep=True))
    for path in addition.directories:
        if not any((p.casefold() if base.dialect != 'linux' else p) ==
                   (path.casefold() if base.dialect != 'linux' else path) for p in result.directories):
            result.directories.append(path)
    return result


def namespace_contract(contract: Contract, prefix: str, keys: set[str]) -> Contract:
    from deceive.binding import TOKEN

    def rewrite(value):
        if isinstance(value, dict):
            return {k: rewrite(v) for k, v in value.items()}
        if isinstance(value, list):
            return [rewrite(v) for v in value]
        if isinstance(value, str):
            return TOKEN.sub(lambda match: '${session.' + prefix + match[2][8:] + '}'
                             if match[2] and match[2].startswith('session.') and match[2][8:] in keys
                             else match[0], value)
        return value
    return Contract.model_validate(rewrite(contract.model_dump(mode='json')))


def _compose(members: list[Profile]) -> tuple[Profile, dict[str, Profile]]:
    first = members[0]
    req = first.requirements
    if not req or not req.base_profile:
        if len(members) != 1:
            raise ValueError("Sharing a listener requires profiles declaring the same base_profile/version")
        return first.model_copy(deep=True), {b.id: first for b in first.behaviors} | {
            'contract/' + c.id: first for c in first.contracts} | {"fallback": first}
    base = profile_base(first)
    if base.requirements and base.requirements.base_profile:
        raise ValueError("Nested base profiles are not supported; select a standalone base profile")
    if base.version != req.base_version:
        raise ValueError(f"Profile {first.id} requires base {base.id}@{req.base_version}; found @{base.version}")
    result = base.model_copy(deep=True)
    result.requirements = None
    result.behaviors = []
    result.contracts = []
    owners = {}
    prior = []
    selected_ids = {p.id for p in members} | {base.id}
    if base.requirements and selected_ids.intersection(base.requirements.incompatible_with):
        raise ValueError(f"Base {base.id} declares an incompatibility with this selection")
    for index, profile in enumerate(members):
        requirements = profile.requirements
        if not requirements or not requirements.base_profile:
            raise ValueError(f"Profile {profile.id} does not declare a base profile for composition")
        other_base = profile_base(profile)
        if content_fingerprint(base) != content_fingerprint(other_base) or requirements.base_version != base.version:
            raise ValueError(f"Profiles {first.id} and {profile.id} require incompatible base profiles/versions")
        if profile.protocol != base.protocol:
            raise ValueError(f"Profile {profile.id} and base {base.id} require different protocols")
        if selected_ids.intersection(requirements.incompatible_with):
            raise ValueError(f"Profile {profile.id} declares an incompatibility with this selection")
        if requirements.scope == "connection" and len(members) > 1:
            raise ValueError(f"Connection-scoped profile {profile.id} requires an exclusive listener")
        for key in profile.identity.model_fields_set:
            if getattr(profile.identity, key) != getattr(base.identity, key):
                raise ValueError(f"Profile {profile.id} conflicts with base {base.id}: identity.{key}")
        for path, content in profile.files.items():
            if path in result.files and result.files[path] != content:
                raise ValueError(f"Profile {profile.id} conflicts with base/another profile: virtual file {path}")
            result.files[path] = content
        if profile.prompt:
            if result.prompt and result.prompt != profile.prompt:
                raise ValueError(f"Profile {profile.id} conflicts with another prompt; use a common base prompt")
            result.prompt = profile.prompt
        for key in ("fallback", "fallback_reply", "cookie_name", "ssh_response_format", "ssh_auth", "device"):
            if key in profile.model_fields_set and getattr(profile, key) != getattr(base, key):
                raise ValueError(f"Profile {profile.id} conflicts with base {base.id}: {key}")
        result.stateful |= profile.stateful
        if profile.command_environment:
            result.command_environment = merge_environment(result.command_environment,
                profile.command_environment, instance_key(profile))
        local_keys = {key for c in profile.contracts for key in set(c.requires) | set(c.effects.state)}
        for contract in profile.contracts:
            route = (Match(path=contract.http.path, method=contract.http.method) if contract.http
                     else Match(command=' '.join([contract.command.program] + contract.command.args))
                     if all('{' not in arg for arg in contract.command.args)
                     else Match(command_regex=re.escape(contract.command.program) + ' .*'))
            routing = Behavior(id=contract.id, kind='contract-command' if contract.command else 'contract-http', match=route)
            for other, other_spec in prior:
                if contract.command and other_spec.kind == 'contract-command':
                    # The merged catalog and argument cases are validated together below.
                    continue
                if instance_key(other) != instance_key(profile) and not _disjoint(route, other_spec.match):
                    raise ValueError(f'Routing conflict: {instance_key(other)}/{other_spec.id} and {instance_key(profile)}/{contract.id}')
            prior.append((profile, routing))
            prefix = f'deception-{index}:'
            compiled_contract = namespace_contract(contract, prefix, local_keys)
            compiled_contract.id = f'd{index}--{contract.id}'
            compiled_contract.requires = {prefix + k: v for k, v in contract.requires.items()}
            compiled_contract.effects.state = {prefix + k: v for k, v in contract.effects.state.items()}
            result.contracts.append(compiled_contract)
            owners['contract/' + compiled_contract.id] = profile
        for spec in profile.behaviors:
            if not _routed(spec.match):
                raise ValueError(f"Profile {profile.id} behavior {spec.id} needs an explicit routing match")
            for other, other_spec in prior:
                if instance_key(other) != instance_key(profile) and not _disjoint(spec.match, other_spec.match):
                    raise ValueError(f"Routing conflict: {other.id}/{other_spec.id} and "
                                     f"{profile.id}/{spec.id}; disjoint routes are not proven")
            prior.append((profile, spec))
            compiled = spec.model_copy(deep=True)
            compiled.id = f"deception-{index}/{spec.id}"
            prefix = f"deception-{index}:"
            compiled.match.state = {prefix + k: v for k, v in spec.match.state.items()}
            compiled.transition = {prefix + k: v for k, v in spec.transition.items()}
            result.behaviors.append(compiled)
            owners[compiled.id] = profile
        result.references.extend(r for r in profile.references if r not in result.references)
        result.limitations.extend(profile.limitations)
    # Base routes and fallback run only after no selected deception responds.
    for spec in base.behaviors:
        compiled = spec.model_copy(deep=True)
        compiled.id = "base/" + spec.id
        result.behaviors.append(compiled)
        owners[compiled.id] = base
    owners["fallback"] = base
    for contract in base.contracts:
        compiled_contract = contract.model_copy(deep=True)
        compiled_contract.id = 'base--' + contract.id
        result.contracts.append(compiled_contract)
        owners['contract/' + compiled_contract.id] = base
    result.schema_version = max(p.schema_version for p in members + [base])
    allowed = set(base.http_versions).intersection(*(set(p.http_versions) for p in members))
    result.http_versions = [v for v in base.http_versions if v in allowed]
    if result.protocol == "http" and not result.http_versions:
        raise ValueError("Profiles and base have no compatible HTTP versions")
    result.id = "composed-" + fingerprint([{"id": p.id, "fingerprint": fingerprint(p)}
                                          for p in members])[:12]
    return Profile.model_validate(result.model_dump()), owners


def resolve(deployment: Deployment, supplied: dict[str, Profile] | None = None) -> Plan:
    plan = Plan()
    selected: dict[str, Profile] = {}
    definitions = {}
    references = {}

    def unique(profiles: list[Profile]) -> list[Profile]:
        result = {}
        for profile in profiles:
            signature = profile.definition_fingerprint or content_fingerprint(profile)
            if profile.id in definitions and definitions[profile.id] != signature:
                raise ValueError(f'Conflicting definitions selected for profile {profile.id}')
            definitions[profile.id] = signature
            if instance_key(profile) in result and fingerprint(result[instance_key(profile)]) != fingerprint(profile):
                raise ValueError(f"Conflicting definitions selected for profile {profile.id}")
            result[instance_key(profile)] = profile
        return sorted(result.values(), key=instance_key)

    def add(listener: Listener, members: list[Profile], injected: bool = False) -> None:
        members = unique(members)
        profile, owners = ((members[0], {b.id: members[0] for b in members[0].behaviors} | {
            'contract/' + c.id: members[0] for c in members[0].contracts} | {'fallback': members[0]})
                           if injected else _compose(members))
        plan.listeners.append(listener)
        plan.profiles[listener.name] = profile
        plan.members[listener.name] = members
        plan.owners[listener.name] = owners
        req = members[0].requirements
        if not injected and req and req.base_profile:
            plan.bases[listener.name] = profile_base(members[0])
        for member in members:
            if instance_key(member) in selected and fingerprint(selected[instance_key(member)]) != fingerprint(member):
                raise ValueError(f"Conflicting definitions selected for profile {member.id}")
            selected[instance_key(member)] = member

    def bound(reference: str | Selection) -> Profile:
        selection = Selection(profile=reference) if isinstance(reference, str) else reference
        return load_profile(selection.profile, organization=selection.organization or deployment.organization,
                            parameters=selection.parameters, instance_id=selection.id)

    for listener in deployment.listeners:
        if listener.enabled:
            injected = supplied is not None and listener.name in supplied
            members = ([supplied[listener.name]] if injected else
                       [bound(ref) for ref in (listener.profiles or [listener.profile])])
            if not injected:
                for member, reference in zip(members, listener.profiles or [listener.profile]):
                    references.setdefault(instance_key(member), reference)
            add(listener.model_copy(deep=True), members, injected)
    groups = {}
    candidates = []
    for deception in deployment.deceptions:
        profile = bound(deception)
        references.setdefault(instance_key(profile), deception if (
            deception.id or deception.organization or deception.parameters) else deception.profile)
        candidates.append(profile)
    for profile in unique(candidates):
        if instance_key(profile) in selected:
            if fingerprint(selected[instance_key(profile)]) != fingerprint(profile):
                raise ValueError(f"Conflicting definitions selected for profile {profile.id}")
            continue
        req = profile.requirements
        base = profile_base(profile) if req and req.base_profile else profile
        if req and req.base_profile:
            compatible = []
            for listener in plan.listeners:
                existing = plan.members[listener.name]
                existing_req = existing[0].requirements
                existing_base = (profile_base(existing[0])
                                 if existing_req and existing_req.base_profile else existing[0])
                if content_fingerprint(existing_base) == content_fingerprint(base) and listener.protocol == req.protocol:
                    compatible.append(listener)
            if len(compatible) > 1:
                raise ValueError(f"Profile {profile.id} matches multiple listeners; select it explicitly in listener.profiles")
            if compatible:
                listener = compatible[0]
                existing = plan.members[listener.name]
                is_base_only = len(existing) == 1 and content_fingerprint(existing[0]) == content_fingerprint(base)
                members = unique(([profile] if is_base_only else existing + [profile]))
                compiled, owners = _compose(members)
                plan.profiles[listener.name] = compiled
                plan.members[listener.name] = members
                plan.owners[listener.name] = owners
                plan.bases[listener.name] = base
                listener.profile = None
                listener.profiles = [references[instance_key(member)] for member in members]
                selected[instance_key(profile)] = profile
                continue
        key = (content_fingerprint(base), _transport(profile), _port(profile))
        groups.setdefault(key, []).append(profile)
    for key, members in sorted(groups.items()):
        base_hash, protocol, port = key
        req = members[0].requirements
        base = profile_base(members[0]) if req and req.base_profile else members[0]
        suffix = fingerprint({"base": base_hash, "protocol": protocol, "port": port})[:8]
        name = "auto-" + re.sub(r"[^a-zA-Z0-9_-]", "-", base.id)[:24] + "-" + suffix
        if name in plan.profiles:
            raise ValueError(f"Automatically generated listener name conflicts: {name}")
        profile, _ = _compose(members)
        versions = profile.http_versions if protocol in {"http", "https"} else ["1.1"]
        if not members[0].requirements:
            versions = ["1.1"]
        selection = ({"profile": references[instance_key(members[0])]} if len(members) == 1
                     and not (members[0].requirements and members[0].requirements.base_profile)
                     else {"profiles": [references[instance_key(p)] for p in members]})
        listener = Listener(name=name, protocol=protocol, **selection,
                            port=port, versions=versions,
                            **deployment.deception_defaults.model_dump())
        add(listener, members)
    ids = {p.id for p in selected.values()}
    for profile in selected.values():
        if profile.requirements and ids.intersection(profile.requirements.incompatible_with):
            raise ValueError(f"Profile {profile.id} declares an incompatibility with another selected profile")
    plan.references = references
    return plan


def validate(plan: Plan, behavior_names: set[str], protocol_names: set[str]) -> None:
    from deceive.behaviors import validate_behavior
    from deceive.contracts import validate_profile

    for listener in plan.listeners:
        profile = plan.profiles[listener.name]
        validate_profile(profile)
        if listener.protocol not in protocol_names:
            raise ValueError(f"Unsupported protocol capability: {listener.protocol}")
        expected = "http" if listener.protocol == "https" else listener.protocol
        if profile.protocol != expected:
            raise ValueError(f"Profile {profile.id} does not support {listener.protocol}")
        if expected == "http" and set(listener.versions) - set(profile.http_versions):
            raise ValueError(f"Unsupported HTTP version for profile {profile.id}")
        if (profile.fallback == "llm" or any(c.mode == 'model' for c in profile.contracts)) and not listener.provider:
            raise ValueError(f"Profile {profile.id} requires a provider; configure provider/model")
        requirements_profiles = plan.members[listener.name] + (
            [plan.bases[listener.name]] if listener.name in plan.bases else [])
        for member in requirements_profiles:
            req = member.requirements
            if req:
                if listener.protocol != req.protocol:
                    raise ValueError(f"Profile {member.id} requires listener protocol {req.protocol}")
                if expected == "http" and set(listener.versions) - set(req.http_versions):
                    raise ValueError(f"Profile {member.id} does not support selected HTTP versions")
                if req.required_port is not None and listener.port != req.required_port:
                    raise ValueError(f"Profile {member.id} requires port {req.required_port}")
                capabilities = CAPABILITIES.get(listener.protocol, set()) | {
                    "behavior:" + name for name in behavior_names}
                missing = set(req.capabilities) - capabilities
                if missing:
                    raise ValueError(f"Profile {member.id} needs unsupported capabilities: {', '.join(sorted(missing))}")
        for spec in profile.behaviors:
            if spec.kind not in behavior_names:
                raise ValueError(f"Unsupported behavior capability: {spec.kind}")
            validate_behavior(spec, profile)
    _validate_bindings(plan.listeners)


def _hosts_overlap(a: str, b: str) -> bool:
    if a == b or a in {"0.0.0.0", "::"} or b in {"0.0.0.0", "::"}:
        return True
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        # Do not perform DNS/network I/O during validation. Unresolved names may
        # alias an address; require literal IPs when proving same-port separation.
        return True


def _validate_bindings(listeners: list[Listener]) -> None:
    bindings = []
    for listener in listeners:
        endpoints = [("tcp", listener.port)]
        if listener.protocol == "https" and "3" in listener.versions:
            endpoints.append(("udp", listener.quic_port if listener.quic_port is not None else listener.port))
        for transport, port in endpoints:
            if port == 0:
                continue
            for other, other_transport, other_port in bindings:
                if transport == other_transport and port == other_port and _hosts_overlap(listener.host, other.host):
                    raise ValueError(f"Listener conflict: {other.name} and {listener.name} both bind "
                                     f"{transport.upper()} port {port}; use explicit listeners with distinct ports/IPs")
            bindings.append((listener, transport, port))
