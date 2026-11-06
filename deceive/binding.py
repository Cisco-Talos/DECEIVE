"""Content-only, one-pass profile binding. No expression or environment evaluation."""
from __future__ import annotations

import hashlib
import base64
from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any

from deceive.models import Organization, Parameter, Profile

TOKEN = re.compile(r'\$\$\{([^{}]+)\}|\$\{([^{}]+)\}')
RUNTIME = ('request.', 'command.', 'session.')
CONTENT = {'identity', 'files', 'prompt', 'behaviors', 'fallback_reply', 'contracts',
           'command_environment'}
FORBIDDEN = {'id', 'kind', 'body_file', 'prompt_file', 'source', 'dialect'}


def render(value: Any, values: dict[str, Any], *, runtime: bool = False,
           pattern: bool = False, _remaining: list[int] | None = None) -> Any:
    remaining = _remaining if _remaining is not None else [8 * 1024 * 1024]

    def charge(text: str) -> str:
        remaining[0] -= len(text.encode('utf-8'))
        if remaining[0] < 0:
            raise ValueError('Template expansion exceeds the 8 MiB bound')
        return text

    if isinstance(value, dict):
        return {render(k, values, runtime=runtime, _remaining=remaining): render(v, values, runtime=runtime,
                pattern=k in {'command_regex', 'pattern'}, _remaining=remaining) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, values, runtime=runtime, pattern=pattern, _remaining=remaining) for v in value]
    if not isinstance(value, str):
        return value
    charge(value)
    whole = TOKEN.fullmatch(value)
    if whole and whole[2] and whole[2] in values and not pattern:
        result = values[whole[2]]
        if not runtime and isinstance(result, str):
            result = re.sub(r'\$\{((?:request|command|session)\.)', lambda m: '$${' + m[1], result)
        return charge(result) if isinstance(result, str) else result

    def substitute(match: re.Match) -> str:
        if match[1]:
            # Preserve escaped runtime tokens through the two binding phases.
            if not runtime and match[1].startswith(RUNTIME):
                return match[0]
            return '${' + match[1] + '}'
        name = match[2]
        if not runtime and name.startswith(RUNTIME):
            return match[0]
        if runtime and not name.startswith(RUNTIME):
            return match[0]
        if name not in values:
            raise ValueError(f'Unresolved placeholder: {name}')
        text = str(values[name]).lower() if type(values[name]) is bool else str(values[name])
        if not runtime:
            text = re.sub(r'\$\{((?:request|command|session)\.)', lambda m: '$${' + m[1], text)
        return charge(re.escape(text) if pattern else text)
    return TOKEN.sub(substitute, value)


def _content(value: Any, values: dict[str, Any], parent: str = '') -> Any:
    if parent in {'body_json', 'files', 'write_files', 'state', 'requires', 'headers',
                  'query', 'cookies', 'json_fields', 'environment'}:
        return render(value, values)
    if isinstance(value, dict):
        return {k: v if k in FORBIDDEN or k in {'body_base64', 'stderr_base64'} else _content(v, values, k) if isinstance(v, (dict, list))
                else render(v, values, pattern=k in {'command_regex', 'pattern'})
                for k, v in value.items()}
    if isinstance(value, list):
        return [_content(v, values) for v in value]
    return render(value, values)


def load_bound(path: Path, raw: dict, *, organization: Path | None = None,
               parameters: dict | None = None, instance_id: str | None = None,
               seen: tuple[Path, ...] = (), allow_unused: bool = False) -> Profile:
    from deceive.config import load_profile, read_yaml, relative_path
    raw = deepcopy(raw)
    if path in seen:
        raise ValueError('Circular profile inheritance')
    definitions = {}
    base = None
    requirement = raw.get('requirements') or {}
    if requirement.get('base_profile'):
        base = load_profile(requirement['base_profile'], path.parent,
                            _seen=seen + (path,))
        definitions.update({k: v.model_dump() for k, v in base.parameters.items()})
    for name, spec in raw.get('parameters', {}).items():
        if name in definitions and Parameter.model_validate(definitions[name]) != Parameter.model_validate(spec):
            raise ValueError(f'Incompatible inherited parameter definition: {name}')
        definitions[name] = spec
    typed = {name: Parameter.model_validate(spec) for name, spec in definitions.items()}
    values = {name: spec.default for name, spec in typed.items()}
    origins = {name: 'profile default' for name in values}
    org = None
    if organization:
        org = Organization.model_validate(read_yaml(organization))
        for name, value in org.values.items():
            if name in typed:
                values[name], origins[name] = value, f'organization:{org.id}@{org.version}'
    for name, value in (parameters or {}).items():
        if name not in typed:
            if allow_unused:
                continue
            raise ValueError(f'Unknown parameter override: {name}')
        values[name], origins[name] = value, 'instance override'
    for name, spec in typed.items():
        try:
            spec.check(values[name])
        except (ValueError, TimeoutError) as exc:
            raise ValueError(f'Parameter {name}: {exc}') from exc
    if base:
        base = load_profile(requirement['base_profile'], path.parent, organization=organization,
                            parameters=values, _seen=seen + (path,), _allow_unused=True)
    raw = dict(raw)
    raw['parameters'] = definitions
    if raw.get('prompt_file'):
        asset = relative_path(path.parent, raw.pop('prompt_file'))
        if asset.stat().st_size > 1048576:
            raise ValueError('Prompt asset exceeds 1 MiB')
        raw['prompt'] = asset.read_text()
    # Text assets opt in explicitly; ordinary body_file remains binary.
    replies = [raw.get('fallback_reply')]
    replies += [item.get(key) for collection in ('contracts', 'behaviors')
                for item in raw.get(collection, []) for key in ('reply', 'fallback', 'error')]
    for reply in replies:
        if not reply:
            continue
        if 'body_template_file' in reply:
            asset = relative_path(path.parent, reply.pop('body_template_file'))
            if asset.stat().st_size > 1048576:
                raise ValueError('Text asset exceeds 1 MiB')
            reply['body'] = asset.read_text()
        if reply.get('body_file'):
            asset = relative_path(path.parent, reply.pop('body_file'))
            if asset.stat().st_size > 1048576:
                raise ValueError('Binary asset exceeds 1 MiB')
            reply['body_base64'] = base64.b64encode(asset.read_bytes()).decode()
    authored = deepcopy(raw)
    for key in CONTENT:
        if key in raw:
            if key == 'files':
                raw[key] = render(raw[key], values)
            else:
                raw[key] = _content(raw[key], values)
    # Binding metadata is recomputed from authored inputs, never template evaluated.
    raw.update(instance_id=instance_id or raw.get('id'), organization_id=org.id if org else None,
               resolved_parameters=values, parameter_origins=origins,
               definition_fingerprint=hashlib.sha256(json.dumps(authored, sort_keys=True).encode()).hexdigest(),
               binding_fingerprint=hashlib.sha256(json.dumps(
                   {'profile': authored, 'values': values, 'organization': org.model_dump() if org else None},
                   sort_keys=True, default=str).encode()).hexdigest())
    if base and base.command_environment and raw.get('command_environment') is not None:
        for field in ('dialect', 'username', 'home', 'shell_version', 'ansi_encoding'):
            raw['command_environment'].setdefault(field, getattr(base.command_environment, field))
    profile = Profile.model_validate(raw)
    profile._bound_base = base
    return profile
