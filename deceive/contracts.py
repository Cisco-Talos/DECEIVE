"""Required interactions and bounded response validation over virtual data."""
from __future__ import annotations

from dataclasses import replace
import asyncio
import base64
from http.cookies import SimpleCookie, CookieError
import json
import ntpath
import posixpath
import re
import time
from urllib.parse import parse_qs, quote

import regex

from deceive.binding import render
from deceive.interaction import Interaction, Response, Session
from deceive.models import Checks, Contract, Effects, Profile, Reply
from deceive.providers import Message, ProviderError
from deceive.ssh_response import parse_reply
from deceive.telemetry import encode


def path_pattern(path: str) -> str:
    chunks = re.split(r'(\{[a-zA-Z_][a-zA-Z0-9_]*\})', path)
    return ''.join('(?P<' + c[1:-1] + '>[^/]+)' if c.startswith('{') and c.endswith('}')
                   else re.escape(c) for c in chunks)


def check_response(checks: Checks, response: Response) -> list[str]:
    failures = []
    text = response.body.decode('utf-8', 'replace')
    for field, actual, expected in [('body', text, checks.text), ('status', response.status, checks.status),
        ('stderr', response.stderr.decode('utf-8', 'replace'), checks.stderr),
        ('exit_status', response.exit_status, checks.exit_status)]:
        if expected is not None and actual != expected:
            failures.append(field + ' differs from required value')
    if checks.body_base64 is not None and response.body != base64.b64decode(checks.body_base64, validate=True):
        failures.append('body bytes differ')
    if any(value not in text for value in checks.contains):
        failures.append('required text missing')
    if checks.pattern and not regex.fullmatch(checks.pattern, text, timeout=0.05):
        failures.append('body pattern differs')
    headers = [(k.decode('ascii').lower(), v.decode('latin-1')) for k, v in response.headers]
    if any((k.lower(), v) not in headers for k, v in checks.headers):
        failures.append('required headers missing')
    if checks.json_fields or checks.json_types:
        try:
            body = json.loads(response.body)
            for key, expected in checks.json_fields.items():
                actual = lookup(body, key)
                if type(actual) is not type(expected) or actual != expected:
                    failures.append(f'JSON field {key} differs')
            types = {'string': (str,), 'integer': (int,), 'number': (int, float),
                     'boolean': (bool,), 'object': (dict,), 'array': (list,), 'null': (type(None),)}
            for key, kind in checks.json_types.items():
                if type(lookup(body, key)) not in types[kind]:
                    failures.append(f'JSON field {key} type differs')
        except (ValueError, KeyError, TypeError, IndexError):
            failures.append('required JSON structure missing')
    return failures


def lookup(value, path: str):
    for key in path.split('.'):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def decode_json(body: bytes, duplicates: str = 'reject'):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if duplicates == 'reject' and key in result:
                raise ValueError('Duplicate JSON object key')
            result[key] = value
        return result
    return json.loads(body, object_pairs_hook=object_pairs)


def flatten(prefix: str, value, output: dict, depth: int = 0) -> None:
    if depth > 32 or len(output) > 256:
        raise ValueError('Request structure exceeds supported bounds')
    if isinstance(value, dict):
        for key, child in value.items():
            flatten(prefix + '.' + str(key), child, output, depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            flatten(prefix + '.' + str(index), child, output, depth + 1)
    else:
        output[prefix] = value


def request_context(interaction: Interaction) -> dict:
    values = {'request.method': interaction.method, 'request.path': interaction.path,
              'request.body': interaction.body.decode('utf-8', 'replace')}
    try:
        query = parse_qs(interaction.query.decode('utf-8', 'replace'), keep_blank_values=True,
                         max_num_fields=128)
    except ValueError:
        query = {}
        values['request.invalid'] = True
    for key, entries in query.items():
        if len(entries) == 1:
            values['request.query.' + key] = entries[0]
    cookies = SimpleCookie()
    repeated = set()
    for key, entry in interaction.headers:
        name, text = key.decode('latin-1').lower(), entry.decode('latin-1')
        # Repeated headers cannot silently choose a privileged value.
        target = 'request.headers.' + name
        if target in values or target in repeated:
            values.pop(target, None)
            repeated.add(target)
        else:
            values[target] = text
        if name == 'cookie':
            try:
                cookies.load(text)
            except CookieError:
                pass
    values.update({'request.cookies.' + key: item.value for key, item in cookies.items()})
    try:
        flatten('request.json', json.loads(interaction.body), values)
    except (ValueError, UnicodeError, RecursionError):
        pass
    return values


def reply_response(reply: Reply, values: dict, behavior: str) -> Response:
    from deceive.behaviors import make_response
    raw = render(reply.model_dump(), values, runtime=True)
    # Location substitutions are URL data, not URL syntax.
    for index, (key, value) in enumerate(reply.headers):
        if key.lower() == 'location':
            escaped = {k: quote(str(v), safe='') for k, v in values.items()}
            raw['headers'][index] = (key, render(value, escaped, runtime=True))
    return make_response(Reply.model_validate(raw), behavior)


def validate_profile(profile: Profile) -> None:
    paths = []
    cases = []
    names = {}
    if profile.command_environment:
        win = profile.command_environment.dialect != 'linux'
        path_module = ntpath if win else posixpath
        seen_paths = set()
        paths_to_check = list(profile.files) + profile.command_environment.directories
        if profile.command_environment.home:
            paths_to_check.append(profile.command_environment.home)
        paths_to_check += [p.path for p in profile.command_environment.programs]
        for path in paths_to_check:
            if (len(path.encode()) > 4096 or '\x00' in path or path.startswith(('//', '\\\\'))
                or not path_module.isabs(path) or path_module.normpath(path) != path
                or (win and not re.match(r'^[A-Za-z]:\\', path))):
                raise ValueError(f'Virtual paths must be bounded normalized absolute paths: {path}')
            key = path.casefold() if win else path
            if path in profile.files:
                if key in seen_paths:
                    raise ValueError(f'Virtual files have conflicting case-insensitive names: {path}')
                seen_paths.add(key)
        if len(profile.command_environment.directories) > 128:
            raise ValueError('Virtual directory declarations exceed supported bounds')
        for program in profile.command_environment.programs:
            for name in [program.name, program.path] + program.aliases:
                key = name if profile.command_environment.dialect == 'linux' else name.casefold()
                if key in names:
                    raise ValueError(f'Duplicate command ownership: {name}')
                names[key] = program.name
    for contract in profile.contracts:
        if contract.http:
            if any(r and (r.stderr or r.stderr_base64) for r in (contract.reply, contract.error, contract.fallback)):
                raise ValueError('HTTP contract replies cannot contain stderr; command contracts may')
            if profile.protocol != 'http' or not contract.http.path.startswith('/'):
                raise ValueError('HTTP contracts need an HTTP profile and absolute path')
            try:
                re.compile(path_pattern(contract.http.path))
            except re.error as exc:
                raise ValueError(f'Invalid path captures in {contract.id}') from exc
            segments = contract.http.path.split('/')
            for other in paths:
                if other.method != contract.http.method:
                    continue
                prior = other.path.split('/')
                if len(prior) == len(segments) and all(a == b or a.startswith('{') or b.startswith('{')
                                                      for a, b in zip(prior, segments)):
                    raise ValueError(f'Routing conflict in HTTP contract {contract.id}')
            paths.append(contract.http)
        else:
            if not profile.command_environment:
                raise ValueError('Command contracts require command_environment')
            key = (contract.command.program, tuple(contract.command.args))
            for prior_program, prior_args in cases:
                if prior_program == key[0] and len(prior_args) == len(key[1]) and all(
                    a == b or a.startswith('{') or b.startswith('{') for a, b in zip(prior_args, key[1])
                ):
                    raise ValueError(f'Ambiguous command case: {contract.id}')
            cases.append(key)
            if contract.command.program not in {p.name for p in profile.command_environment.programs}:
                raise ValueError(f'Undeclared program in contract {contract.id}')
        if contract.mode == 'model' and not (contract.checks.model_dump(exclude_defaults=True)):
            raise ValueError(f'Model contract {contract.id} requires output checks')
        if contract.checks.pattern:
            regex.compile(contract.checks.pattern)
        if contract.endpoint and not profile.command_environment:
            raise ValueError('Command endpoints require command_environment')
        for key in contract.effects.state:
            if key in {'hostname', 'os', 'kernel', 'architecture'}:
                raise ValueError('Contract effects cannot change deployment identity')
        # Dynamic replies are checked on each request; fixed replies fail at startup.
        for reply in ([contract.reply] if contract.mode == 'deterministic' and not contract.endpoint else []) + (
            [contract.fallback] if contract.fallback else []):
            if '${request.' not in reply.model_dump_json() and '${command.' not in reply.model_dump_json() and '${session.' not in reply.model_dump_json():
                failures = check_response(contract.checks, reply_response(reply, {}, contract.id))
                if failures:
                    raise ValueError(f'Contract {contract.id}: ' + '; '.join(failures))


def apply_effects(profile: Profile, contract: Contract, session: Session, values: dict) -> None:
    from deceive.commands import virtual_path, check_capacity
    effects = Effects.model_validate(render(contract.effects.model_dump(), values, runtime=True)).model_dump()
    if set(effects['state']) & {'hostname', 'os', 'kernel', 'architecture'}:
        raise ValueError('Contract effects cannot change deployment identity')
    for path, text in effects['write_files'].items():
        key = virtual_path(profile, session, path)
        session.virtual_files[key] = str(text).encode()
        session.removed_files.discard(key)
    for path in effects['remove_files']:
        key = virtual_path(profile, session, path)
        session.virtual_files.pop(key, None)
        session.removed_files.add(key)
    session.state.update(effects['state'])
    check_capacity(session)


async def execute(runtime, profile: Profile, contract: Contract, session: Session,
                  interaction: Interaction, values: dict, *, command: bool = False) -> Response:
    from deceive.runtime import SYSTEM_PROMPT, SSH_JSON_PROMPT, HTTP_PROMPT
    behavior = 'contract/' + contract.id
    values.update({'session.' + k: v for k, v in session.state.items()})
    if any(session.state.get(key) != value for key, value in contract.requires.items()):
        return reply_response(contract.error, values, behavior)
    checks = Checks.model_validate(render(contract.checks.model_dump(), values, runtime=True))
    if contract.mode == 'deterministic':
        result = reply_response(contract.reply, values, behavior)
        failures = check_response(checks, result)
        if failures:
            raise ValueError(f'Contract {contract.id}: ' + '; '.join(failures))
    else:
        listener = runtime.listeners[session.listener]
        facts = {'identity': profile.identity.model_dump(), 'parameters': profile.resolved_parameters,
                 'state': session.state, 'files': profile.files | {
                     p: b.decode('utf-8', 'replace') for p, b in session.virtual_files.items()
                 }, 'input': values}
        for removed in session.removed_files:
            facts['files'].pop(removed, None)
        messages = [Message('system', SYSTEM_PROMPT + (SSH_JSON_PROMPT if command else HTTP_PROMPT)
                    + '\n' + json.dumps(facts) + '\n' + profile.prompt + '\n'
                    + render(contract.guidance, values, runtime=True))] + list(session.history) + [
                    Message('user', interaction.command if command else json.dumps(values))]
        result = None
        deadline = time.monotonic() + runtime.limits.llm_seconds
        for attempt in (1, 2):
            text = await asyncio.wait_for(runtime.invoke(listener, messages, session),
                                          max(0, deadline - time.monotonic()))
            try:
                if command:
                    candidate = parse_reply(text)
                else:
                    reply = Reply.model_validate(json.loads(text))
                    if reply.body_file:
                        raise ValueError('Model responses cannot select assets')
                    candidate = replace(reply_response(reply, {}, behavior), origin='llm', model_output=text)
                failures = check_response(checks, candidate)
            except (ValueError, TypeError, RecursionError):
                failures = ['response format is invalid']
            if not failures:
                result = candidate
                result.behavior = behavior
                break
            runtime.emit(session, 'LLM response', details=encode(text), response_origin='llm',
                         response_stage='attempt', attempt=attempt, validation_errors=failures,
                         behavior=behavior, request_id=interaction.request_id,
                         interactive=interaction.interactive)
            messages += [Message('assistant', text), Message('user',
                'Repair only the current response: ' + '; '.join(failures))]
        if result is None:
            if contract.fallback:
                result = reply_response(contract.fallback, values, behavior)
                if check_response(checks, result):
                    raise ProviderError('Contract fallback failed output validation')
            else:
                return Response(status=503, stderr=b'Command failed.\n' if command else b'',
                                body=b'' if command else b'Service unavailable\n',
                                exit_status=1, behavior=behavior)
    apply_effects(profile, contract, session, values)
    return result


async def respond(runtime, profile: Profile, session: Session, interaction: Interaction) -> Response | None:
    if interaction.protocol == 'ssh':
        return None
    values = request_context(interaction)
    for contract in profile.contracts:
        if not contract.http or interaction.method != contract.http.method:
            continue
        match = re.fullmatch(path_pattern(contract.http.path), interaction.path)
        if not match:
            continue
        context = values | {'request.path.' + k: v for k, v in match.groupdict().items()}
        http = contract.http
        if http.json_fields or (contract.endpoint and contract.endpoint.source == 'json') or '${request.json.' in contract.model_dump_json():
            try:
                parsed = decode_json(interaction.body, http.json_duplicates)
                context = {k: v for k, v in context.items() if not k.startswith('request.json.')}
                flatten('request.json', parsed, context)
            except (ValueError, TypeError, RecursionError, UnicodeError):
                return reply_response(contract.error, context, 'contract/' + contract.id)
        expected = {**{'request.query.' + k: v for k, v in http.query.items()},
                    **{'request.headers.' + k.lower(): v for k, v in http.headers.items()},
                    **{'request.cookies.' + k: v for k, v in http.cookies.items()},
                    **{'request.json.' + k: v for k, v in http.json_fields.items()}}
        if context.get('request.invalid') or any(context.get(k) != v or type(context.get(k)) is not type(v) for k, v in expected.items()) or (
            http.body_contains is not None and http.body_contains.encode() not in interaction.body
        ) or any(session.state.get(k) != v for k, v in contract.requires.items()):
            return reply_response(contract.error, context, 'contract/' + contract.id)
        if contract.endpoint:
            from deceive.commands import run_endpoint
            return await run_endpoint(runtime, profile, contract, session, interaction, context)
        return await execute(runtime, profile, contract, session, interaction, context)
    return None
