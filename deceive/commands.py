"""A bounded command service shared by network adapters. All state is virtual."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
import ntpath
import posixpath
import re
import shlex
from urllib.parse import parse_qs

from deceive.interaction import Interaction, Response, Session
from deceive.models import Behavior, Profile
from deceive import virtual_files


@dataclass(frozen=True)
class CommandRequest:
    text: str
    dialect: str
    interactive: bool = False


@dataclass(frozen=True)
class CommandResult:
    stdout: bytes = b''
    stderr: bytes = b''
    exit_status: int = 0
    end_process: bool = False

    @classmethod
    def from_response(cls, response: Response) -> CommandResult:
        return cls(response.body, response.stderr, response.exit_status, response.close)


@dataclass(frozen=True)
class LiteralWord:
    value: str
    quoted: bool = False
    operator: bool = False
    start: int = 0
    end: int = 0


def windows(profile: Profile) -> bool:
    return bool(profile.command_environment and profile.command_environment.dialect != 'linux')


def home(profile: Profile, session: Session) -> str:
    config = profile.command_environment
    if config and config.home:
        return config.home
    return ('C:\\Users\\' + session.username if windows(profile) else
            '/root' if session.username == 'root' else '/home/' + session.username)


def initial_state(profile: Profile, session: Session) -> None:
    session.state.setdefault('cwd', home(profile, session))
    for key, value in profile.command_environment.environment.items():
        session.state.setdefault('env:' + (key.upper() if windows(profile) else key), value)


def virtual_path(profile: Profile, session: Session, name: str) -> str:
    if '\x00' in name or len(name.encode()) > 4096:
        raise ValueError('Virtual path exceeds supported bounds')
    cwd = session.state.get('cwd', home(profile, session))
    if windows(profile):
        if name.startswith(('\\\\', '//')) or re.match(r'^[A-Za-z]:[^\\/]', name):
            raise ValueError('UNC and drive-relative paths are unsupported')
        result = ntpath.normpath(ntpath.join(cwd, name))
        if not re.match(r'^[A-Za-z]:\\', result):
            raise ValueError('Expected virtual drive path')
        candidates = list(profile.files) + list(session.virtual_files) + list(session.virtual_directories)
        candidates += profile.command_environment.directories + [home(profile, session)]
        for candidate in list(candidates):
            parent = ntpath.dirname(candidate)
            while parent:
                candidates.append(parent)
                next_parent = ntpath.dirname(parent)
                if next_parent == parent:
                    break
                parent = next_parent
        for candidate in candidates:
            if candidate.casefold() == result.casefold():
                return candidate
        parent, tail = ntpath.split(result)
        for candidate in candidates:
            if candidate.casefold() == parent.casefold():
                return ntpath.join(candidate, tail)
        return result
    name = home(profile, session) + name[1:] if name == '~' or name.startswith('~/') else name
    return '/' + posixpath.normpath(posixpath.join(cwd, name)).lstrip('/')


def check_capacity(session: Session) -> None:
    if (len(session.virtual_files) + len(session.virtual_directories) + len(session.removed_files) > virtual_files.MAX_NODES
        or sum(len(v) for v in session.virtual_files.values()) > virtual_files.MAX_BYTES
        or len(session.state) > 128
        or any(not isinstance(k, str) or not isinstance(v, str) or len(k) > 128 or len(v) > 4096
               for k, v in session.state.items())):
        raise ValueError('Virtual state capacity exceeded')


def file_view(profile: Profile, session: Session) -> tuple[dict[str, bytes], set[str]]:
    if not windows(profile):
        copied = profile.model_copy(deep=True)
        copied.behaviors.append(Behavior(id='command-files', kind='virtual_files',
            options={'directories': profile.command_environment.directories}))
        return virtual_files.view(copied, session)
    files = {p: v.encode() for p, v in profile.files.items() if p not in session.removed_files}
    files.update(session.virtual_files)
    dirs = set(profile.command_environment.directories) | session.virtual_directories | {home(profile, session)}
    for path in list(files) + list(dirs):
        while path and ntpath.dirname(path) != path:
            path = ntpath.dirname(path)
            dirs.add(path)
    return files, dirs


def words_for(request: CommandRequest) -> list[str]:
    if request.dialect == 'linux':
        return shlex.split(request.text)
    return [word.value for word in windows_words(request.text)]


def windows_words(text: str) -> list[LiteralWord]:
    # Bounded literal grammar: no expression, script, expansion, or pipeline evaluation.
    pattern = r'"([^"\r\n]*)"|\'([^\'\r\n]*)\'|(>>|&&|\|\||[<>|;&])|([^\s"\'<>|;&]+)'
    words, cursor = [], 0
    for match in re.finditer(pattern, text):
        if text[cursor:match.start()].strip():
            raise ValueError('Unsupported quoting')
        word = LiteralWord(next(g for g in match.groups() if g is not None),
            quoted=match[1] is not None or match[2] is not None,
            operator=match[3] is not None, start=match.start(), end=match.end())
        if (word.operator and word.value in {'>', '>>'} and words and
                not words[-1].quoted and words[-1].value.isdecimal() and
                words[-1].end == word.start):
            raise ValueError('File descriptor redirection is unsupported')
        words.append(word)
        cursor = match.end()
    if text[cursor:].strip():
        raise ValueError('Unsupported quoting')
    redirects = [i for i, word in enumerate(words) if word.operator and word.value in {'>', '>>'}]
    if redirects and (len(redirects) != 1 or redirects[0] != len(words) - 2):
        raise ValueError('Only one trailing literal redirection is supported')
    return words


def unwrap(request: CommandRequest) -> CommandRequest:
    words = words_for(request)
    if not words:
        return request
    name = ntpath.basename(words[0]).lower()
    if name in ('cmd', 'cmd.exe') and request.dialect != 'linux':
        args = windows_words(request.text)[1:]
        if args and args[0].value.lower() == '/d':
            args = args[1:]
        if len(args) < 2 or args[0].value.lower() != '/c':
            raise ValueError('Only cmd /c single-command wrappers are supported')
        text = args[1].value if len(args) == 2 else join_literals(args[1:])
        return CommandRequest(text, 'cmd', False)
    if name in ('powershell', 'powershell.exe', 'pwsh', 'pwsh.exe') and request.dialect != 'linux':
        args = windows_words(request.text)[1:]
        while args and args[0].value.lower() in ('-noprofile', '-noninteractive'):
            args = args[1:]
        if len(args) < 2 or args[0].value.lower() != '-command':
            raise ValueError('Only PowerShell -Command single-command wrappers are supported')
        dialect = 'powershell-7' if name.startswith('pwsh') else 'powershell-5.1'
        if request.dialect.startswith('powershell') and dialect != request.dialect:
            raise ValueError('Wrapper does not match the configured PowerShell version')
        return CommandRequest(args[1].value if len(args) == 2 else join_literals(args[1:]), dialect, False)
    return request


def join_literals(words: list[LiteralWord]) -> str:
    """Retain quoted data and empty operands when reparsing a bounded wrapper."""
    if any('"' in word.value or '\n' in word.value or '\r' in word.value for word in words):
        raise ValueError('Unsupported nested quoting')
    return ' '.join('"' + word.value + '"' if not word.operator and (
        word.quoted or not word.value or re.search(r"[\s'<>|;&]", word.value))
        else word.value for word in words)


def program_names(profile: Profile) -> dict:
    output = {}
    for program in profile.command_environment.programs:
        for name in [program.name, program.path] + program.aliases:
            output[name if not windows(profile) else name.casefold()] = program
    return output


def arguments(pattern: list[str], supplied: list[str]) -> dict | None:
    if len(pattern) != len(supplied):
        return None
    result = {}
    for index, (expected, value) in enumerate(zip(pattern, supplied)):
        result['command.args.' + str(index)] = value
        if re.fullmatch(r'\{[A-Za-z_][A-Za-z0-9_]*\}', expected):
            result['command.' + expected[1:-1]] = value
        elif expected != value:
            return None
    return result


async def respond(runtime, profile: Profile, session: Session, interaction: Interaction) -> Response | None:
    if not profile.command_environment:
        return None
    from deceive.contracts import execute, reply_response
    initial_state(profile, session)
    request = CommandRequest(interaction.command, profile.command_environment.dialect, interaction.interactive)
    try:
        request = unwrap(request)
        words = words_for(request)
    except ValueError:
        return Response(stderr=b'Syntax error\n', exit_status=2, behavior='command/syntax')
    if not words:
        return Response(exit_status=session.last_exit_status, behavior='command/empty')
    operators = ([word.value for word in windows_words(request.text) if word.operator]
                 if request.dialect != 'linux' else words)
    if any(v in {'|', '||', '&&', ';', '&', '<'} for v in operators) or any(c in request.text for c in '\r\n'):
        return None
    name, args = words[0], words[1:]

    def status(result: Response, *, native: bool = False) -> Response:
        if request.dialect.startswith('powershell'):
            session.state['ps_success'] = 'True' if result.exit_status == 0 else 'False'
            if native:
                session.state['ps_native_exit'] = str(result.exit_status)
        return result

    registry = program_names(profile)
    key = name if not windows(profile) else name.casefold()
    program = registry.get(key)
    if program:
        for contract in profile.contracts:
            if contract.command and contract.command.program == program.name:
                values = arguments(contract.command.args, args)
                if values is not None:
                    values['command.program'] = program.name
                    return status(await execute(runtime, profile, contract, session,
                        replace(interaction, command=request.text), values, command=True), native=True)
        if args in (['--help'], ['/?'], ['-?']) and program.help is not None:
            return status(Response(body=program.help.encode(), behavior='command/help'), native=True)
        if args in (['--version'], ['-Version']) and program.version is not None:
            return status(Response(body=program.version.encode(), behavior='command/version'), native=True)
        cases = [c for c in profile.contracts if c.command and c.command.program == program.name]
        if cases:
            return status(reply_response(cases[0].error, {'command.program': program.name},
                                  'contract/' + cases[0].id), native=True)
        return Response(stderr=b'Invalid arguments\n', exit_status=1, behavior='command/arguments')
    lookup_command = name.lower() if windows(profile) else name
    if lookup_command in ('which', 'where', 'where.exe', 'get-command') and len(args) == 1:
        wanted = args[0] if not windows(profile) else args[0].casefold()
        found = registry.get(wanted)
        builtins = linux_names() if not windows(profile) else windows_names(request.dialect)
        if found:
            path = found.path
        elif lookup_command == 'get-command' and wanted == 'type':
            return Response(body=b'Alias type -> Get-Content\r\n', behavior='command/discovery')
        elif wanted in builtins:
            path = '/usr/bin/' + wanted if not windows(profile) else (
                'Function ' + wanted if request.dialect.startswith('powershell') else 'C:\\Windows\\System32\\' + wanted + '.exe')
        else:
            return Response(exit_status=1, behavior='command/discovery')
        return Response(body=(path + ('\r\n' if windows(profile) else '\n')).encode(), behavior='command/discovery')
    if request.dialect == 'linux':
        from deceive.behaviors import identity
        copied = profile.model_copy(deep=True)
        copied.protocol = 'ssh'
        spec = Behavior(id='command/files', kind='virtual_files', options={
            'directories': profile.command_environment.directories})
        copied.behaviors.append(spec)
        translated = replace(interaction, protocol='ssh', command=request.text)
        result = virtual_files.respond(copied, spec, translated, session)
        if result is None:
            result = identity(copied, Behavior(id='command/identity'), translated, session)
        if result is None and name == 'echo' and not any(v in {'>', '>>'} for v in args):
            result = Response(body=(' '.join(args) + '\n').encode())
        if result is None and name == 'export' and len(args) == 1 and '=' in args[0]:
            k, value = args[0].split('=', 1)
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', k):
                session.state['env:' + k] = value
                result = Response()
        if result is not None:
            if result.behavior == 'fallback':
                result.behavior = 'command/' + name
            check_capacity(session)
        return result
    result = windows_command(profile, session, request, words)
    check_capacity(session)
    return status(result, native=name.lower() in {'hostname', 'whoami', 'whoami.exe'}) if result is not None else None


def linux_names() -> set[str]:
    return {'hostname', 'whoami', 'id', 'uname', 'pwd', 'cat', 'ls', 'cd', 'touch', 'mkdir',
            'rm', 'echo', 'exit', 'logout', 'which', 'export', 'wc', 'printf'}


def windows_names(dialect: str) -> set[str]:
    common = {'hostname', 'whoami', 'exit'}
    return common | ({'ver', 'where', 'cd', 'dir', 'type', 'echo', 'mkdir', 'del', 'set'}
        if dialect == 'cmd' else {'get-command', 'get-location', 'set-location', 'get-childitem',
            'get-content', 'set-content', 'add-content', 'new-item', 'remove-item', 'write-output'})


def text_codec(data: bytes, default: str) -> tuple[str, int]:
    # Longest BOMs first: UTF-32LE starts with the UTF-16LE marker.
    for marker, codec in ((b'\xff\xfe\x00\x00', 'utf-32-le'), (b'\x00\x00\xfe\xff', 'utf-32-be'),
                          (b'\xef\xbb\xbf', 'utf-8'), (b'\xff\xfe', 'utf-16-le'),
                          (b'\xfe\xff', 'utf-16-be')):
        if data.startswith(marker):
            return codec, len(marker)
    return default, 0


def windows_command(profile: Profile, session: Session, request: CommandRequest, words: list[str]) -> Response | None:
    name, args = words[0].lower(), words[1:]
    ps = request.dialect.startswith('powershell')
    if ps and name == 'type':
        name = 'get-content'
    newline = '\r\n'

    def output(text: str = '', status: int = 0) -> Response:
        return Response(body=text.encode(), exit_status=status, behavior='command/' + name)

    def error(message: str) -> Response:
        return Response(stderr=(message + newline).encode(), exit_status=1, behavior='command/' + name)

    if name == 'hostname' and not args:
        return output(profile.identity.hostname + newline)
    if name in ('whoami', 'whoami.exe') and not args:
        return output(profile.identity.hostname.lower() + '\\' + session.state.get('user', session.username) + newline)
    if name == 'ver' and not args and not ps:
        return output(profile.identity.os + newline)
    if request.text.strip().lower() == '$psversiontable.psversion' and ps:
        return output((profile.command_environment.shell_version or ('5.1' if request.dialect == 'powershell-5.1' else '7.0')) + newline)
    if request.text.strip().lower() == 'echo %errorlevel%' and not ps:
        return output(str(session.last_exit_status) + newline)
    if request.text.strip().lower() in ('write-output $lastexitcode', 'echo $lastexitcode') and ps:
        return output(session.state.get('ps_native_exit', '0') + newline)
    if request.text.strip().lower() in ('write-output $?', 'echo $?') and ps:
        return output(session.state.get('ps_success', 'True') + newline)
    if name == 'exit' and len(args) <= 1:
        if args and not re.fullmatch(r'[0-9]{1,3}', args[0]):
            return error('Invalid exit status')
        status = int(args[0]) if args else session.last_exit_status
        if status > 255:
            return error('Invalid exit status')
        return Response(close=True, exit_status=status, behavior='command/exit')
    if name == 'set' and not ps:
        if not args:
            return output(''.join(k[4:] + '=' + v + newline for k, v in sorted(session.state.items()) if k.startswith('env:')))
        if len(args) == 1 and '=' in args[0]:
            key, value = args[0].split('=', 1)
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                session.state['env:' + key.upper()] = value
                return output()
        if len(args) == 1:
            value = session.state.get('env:' + args[0].upper())
            return output(args[0].upper() + '=' + value + newline) if value is not None else error('Environment variable not defined')
        return error('Invalid environment arguments')
    if ps and re.fullmatch(r'\$env:[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+', request.text, re.I):
        key, value = request.text.split('=', 1)
        session.state['env:' + key.strip()[5:].upper()] = value.strip().strip('"\'')
        return output()
    if name in ('echo', 'write-output'):
        tokens = windows_words(request.text)
        if len(args) >= 2 and tokens[-2].operator and args[-2] in ('>', '>>'):
            return write_file(profile, session, args[-1], ' '.join(args[:-2]) + newline,
                              append=args[-2] == '>>', encoding='utf-16' if request.dialect == 'powershell-5.1' else 'utf-8')
        values = []
        for value in args:
            if not ps and re.fullmatch(r'%[A-Za-z_][A-Za-z0-9_]*%', value):
                value = session.state.get('env:' + value[1:-1].upper(), value)
            elif ps and value.lower().startswith('$env:'):
                value = session.state.get('env:' + value[5:].upper(), '')
            values.append(value)
        return output(' '.join(values) + newline)
    files, directories = file_view(profile, session)
    if name in ('cd', 'get-location', 'set-location'):
        if name in ('get-location', 'cd') and not args:
            return output(session.state['cwd'] + newline)
        if len(args) == 1:
            path = virtual_path(profile, session, args[0])
            if path not in directories:
                return error('The system cannot find the path specified.')
            session.state['cwd'] = path
            return output()
        return error('Invalid location arguments')
    if name in ('dir', 'get-childitem') and len(args) <= 1:
        path = virtual_path(profile, session, args[0] if args else '.')
        if path not in directories and path not in files:
            return error('The system cannot find the path specified.')
        children = [path] if path in files else sorted(p for p in files.keys() | directories if p != path and ntpath.dirname(p).casefold() == path.casefold())
        return output(''.join(ntpath.basename(p) + newline for p in children))
    if name in ('type', 'get-content') and len(args) == 1:
        path = virtual_path(profile, session, args[0])
        if path not in files:
            return error('The system cannot find the file specified.')
        if name == 'type':
            return Response(body=files[path], behavior='command/type')
        data = files[path]
        default = profile.command_environment.ansi_encoding if request.dialect == 'powershell-5.1' else 'utf-8'
        encoding, offset = text_codec(data, default)
        return output(''.join(line + newline for line in data[offset:].decode(encoding, 'replace').splitlines()))
    if name in ('set-content', 'add-content'):
        if len(args) == 4 and args[0].lower() == '-path' and args[2].lower() == '-value':
            args = [args[1], args[3]]
        if len(args) == 2:
            encoding = profile.command_environment.ansi_encoding if request.dialect == 'powershell-5.1' else 'utf-8'
            if name == 'add-content':
                existing = files.get(virtual_path(profile, session, args[0]), b'')
                encoding, _ = text_codec(existing, encoding)
            return write_file(profile, session, args[0], args[1] + newline,
                append=name == 'add-content', encoding=encoding)
        return error('Invalid content arguments')
    if name in ('mkdir', 'new-item'):
        directory = name == 'mkdir'
        if name == 'new-item' and len(args) == 4 and args[0].lower() == '-itemtype' and args[2].lower() == '-path':
            directory, args = args[1].lower() == 'directory', [args[3]]
        elif name == 'new-item':
            return error('Use New-Item -ItemType File|Directory -Path PATH')
        if len(args) != 1:
            return error('Invalid item arguments')
        path = virtual_path(profile, session, args[0])
        if path in files or path in directories:
            return error('An item already exists.')
        if ntpath.dirname(path) not in directories:
            return error('The system cannot find the path specified.')
        if directory:
            session.virtual_directories.add(path)
        else:
            session.virtual_files[path] = b''
            session.removed_files.discard(path)
        return output()
    if name in ('del', 'remove-item') and len(args) == 1:
        path = virtual_path(profile, session, args[0])
        if path not in files:
            return error('The system cannot find the file specified.')
        session.virtual_files.pop(path, None)
        session.removed_files.add(path)
        return output()
    if name in windows_names(request.dialect):
        return error('Unsupported arguments')
    return None


def write_file(profile: Profile, session: Session, name: str, text: str, *, append: bool, encoding: str) -> Response:
    path = virtual_path(profile, session, name)
    files, directories = file_view(profile, session)
    if path in directories or ntpath.dirname(path) not in directories:
        return Response(stderr=b'The system cannot find the path specified.\r\n', exit_status=1,
                        behavior='command/write')
    try:
        data = text.encode(encoding)
    except UnicodeError:
        return Response(stderr=b'Text is not representable in the selected encoding.\r\n', exit_status=1)
    if append:
        prior = files.get(path, b'')
        if prior and encoding == 'utf-16' and data.startswith(b'\xff\xfe'):
            data = data[2:]
        data = prior + data
    session.virtual_files[path] = data
    session.removed_files.discard(path)
    check_capacity(session)
    return Response(behavior='command/write')


async def run_endpoint(runtime, profile, contract, session, interaction, context) -> Response:
    from deceive.contracts import reply_response, check_response, apply_effects, decode_json
    endpoint = contract.endpoint
    try:
        if endpoint.source == 'json':
            command = decode_json(interaction.body, contract.http.json_duplicates)[endpoint.field]
        else:
            data = interaction.query if endpoint.source == 'query' else interaction.body
            values = parse_qs(data.decode('utf-8'), keep_blank_values=True, max_num_fields=128)
            entries = values.get(endpoint.field, [])
            if len(entries) != 1:
                raise ValueError('Expected exactly one command field')
            command = entries[0]
        if not isinstance(command, str) or len(command.encode()) > runtime.limits.input_bytes:
            raise ValueError('Invalid command input')
    except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        return reply_response(contract.error, context, 'contract/' + contract.id)
    # Share only app/files state. A web command is always a fresh process.
    process = replace(session, username=profile.command_environment.username,
                      state={k: v for k, v in session.state.items() if k not in {'cwd', 'user', 'uid', 'ps_success', 'ps_native_exit'} and not k.startswith('env:')},
                      last_exit_status=0)
    result = await respond(runtime, profile, process, replace(interaction, protocol='ssh', command=command, interactive=False))
    if result is None and profile.fallback == 'llm':
        from deceive.runtime import SYSTEM_PROMPT, SSH_JSON_PROMPT
        from deceive.providers import Message
        from deceive.ssh_response import parse_reply
        files, directories = file_view(profile, process)
        facts = {'identity': profile.identity.model_dump(), 'state': process.state,
                 'files': {k: v.decode('utf-8', 'replace') for k, v in files.items()},
                 'directories': sorted(directories), 'dialect': profile.command_environment.dialect}
        text = await runtime.invoke(runtime.listeners[session.listener], [
            Message('system', SYSTEM_PROMPT + SSH_JSON_PROMPT + json.dumps(facts) + profile.prompt),
            *session.history, Message('user', command)], session)
        result = parse_reply(text)
    if result is None:
        result = Response(stderr=b'Command not found\n', exit_status=127, behavior='command/missing')
    check_capacity(process)
    process.state.update(result.transition)
    session.virtual_files = process.virtual_files
    session.virtual_directories = process.virtual_directories
    session.removed_files = process.removed_files
    for key, value in process.state.items():
        if key not in {'cwd', 'user', 'uid', 'ps_success', 'ps_native_exit'} and not key.startswith('env:'):
            session.state[key] = value
    payload = CommandResult.from_response(result)
    if endpoint.response == 'json':
        import base64
        body = json.dumps({'stdout': payload.stdout.decode('utf-8', 'replace'),
                           'stderr': payload.stderr.decode('utf-8', 'replace'),
                           'stdout_base64': base64.b64encode(payload.stdout).decode(),
                           'stderr_base64': base64.b64encode(payload.stderr).decode(),
                           'exit_status': payload.exit_status}).encode()
        headers = [(b'content-type', b'application/json')]
    else:
        body, headers = payload.stdout + payload.stderr, []
    response = Response(body=body, headers=headers, behavior='contract/' + contract.id,
                        origin=result.origin, model_output=result.model_output)
    failures = check_response(contract.checks, response)
    if failures:
        raise ValueError('Command endpoint output failed validation: ' + '; '.join(failures))
    apply_effects(profile, contract, session, context)
    return response
