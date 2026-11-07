"""Virtual interpreters and authoritative device objects; no host I/O."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import fnmatch
import ipaddress
import posixpath
import re
import shlex
from typing import TYPE_CHECKING

from deceive.interaction import Interaction, Response, Session
from deceive.models import DevicePack, Profile
from deceive import virtual_files

if TYPE_CHECKING:
    from deceive.runtime import Runtime


@dataclass
class Frame:
    interpreter: str
    cwd: str
    environment: dict[str, str]


@dataclass
class DeviceSession:
    hostname: str
    interpreter: str = 'bash'
    stack: list[Frame] = field(default_factory=list)
    processes: dict[int, str] = field(default_factory=lambda: {1: 'init', 120: 'sshd', 240: 'worker'})
    configuration: dict[str, str] = field(default_factory=lambda: {'interface': 'GigabitEthernet0/0',
                                                                  'description': 'uplink', 'shutdown': 'no'})
    startup: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, dict[str, str]] = field(default_factory=dict)
    executable_additions: list[str] = field(default_factory=list)
    executable_removals: list[str] = field(default_factory=list)
    mode: str = 'user'
    application: object = None
    dialogue: dict[str, str] | None = None
    revision: int = 0
    resource_sample: int = 0
    resource_seconds: float = 0.0
    process_cpu_seconds: dict[int, float] = field(default_factory=lambda: {1: 1., 120: 1., 240: 12.})


@dataclass
class SessionAction(Response):
    """A validated response with ordered terminal chunks and virtual effects."""


def pack(profile: Profile) -> DevicePack:
    return profile.device or DevicePack()


def home(profile: Profile, session: Session) -> str:
    if profile.command_environment:
        if profile.command_environment.home:
            return profile.command_environment.home
        if profile.command_environment.dialect != 'linux':
            return 'C:\\Users\\' + session.username
    spec = pack(profile)
    if spec.home:
        return spec.home.replace('{user}', session.username)
    if session.username == 'root':
        return '/var/root' if spec.platform == 'macos' else '/root'
    return ('/Users/' if spec.platform == 'macos' else '/home/') + session.username


def ensure(profile: Profile, session: Session) -> DeviceSession:
    if session.device is None:
        session.device = DeviceSession(profile.identity.hostname)
        session.device.interpreter = pack(profile).interpreter
        session.device.startup = dict(session.device.configuration) | {'hostname': profile.identity.hostname}
        session.state.setdefault('cwd', home(profile, session))
    return session.device


def resources(profile: Profile, session: Session) -> dict:
    """A complete bounded resource inventory shared by commands, apps and models."""
    device = ensure(profile, session)
    processes = []
    for pid, name in sorted(device.processes.items()):
        cpu = round(1.2 + .1 * (device.resource_sample % 5), 1) if pid == 240 else .1 if pid == 120 else 0.0
        resident = 32768 if pid == 240 else 8192 if pid == 120 else 4096
        processes.append({'pid': pid, 'command': name,
                          'user': 'root' if pid in {1, 120} else session.username,
                          'cpu_percent': cpu, 'resident_kib': resident,
                          'virtual_kib': resident * 4, 'state': 'R' if pid == 240 else 'S',
                          'cpu_seconds': device.process_cpu_seconds.get(pid, 0.)})
    total = 4194304
    used = 1048576 + sum(p['resident_kib'] for p in processes)
    return {'complete': True, 'uptime_seconds': 86400 + int(device.resource_seconds), 'load_average': [.03, .02, .01],
            'memory_total_kib': total, 'memory_used_kib': used,
            'memory_free_kib': total - used, 'swap_total_kib': 2097152,
            'swap_used_kib': 0, 'cpu_user_percent': round(sum(p['cpu_percent'] for p in processes), 1),
            'cpu_system_percent': .2, 'processes': processes}


def sample_resources(profile: Profile, session: Session, seconds: float) -> None:
    device = ensure(profile, session)
    for process in resources(profile, session)['processes']:
        pid = process['pid']
        device.process_cpu_seconds[pid] = process['cpu_seconds'] + seconds * process['cpu_percent'] / 100
    device.resource_seconds += seconds
    device.resource_sample += 1


def network_interfaces(profile: Profile, session: Session) -> dict:
    device = ensure(profile, session)
    name = device.configuration['interface'] if pack(profile).platform == 'ios' else {
        'linux': 'eth0', 'macos': 'en0', 'freebsd': 'em0'}[pack(profile).platform]
    status = ('administratively down' if device.configuration['shutdown'] == 'yes' else 'up')
    return {'complete': True, 'interfaces': [{
        'name': name, 'address': '192.0.2.10', 'prefix_length': 24,
        'status': status, 'protocol': 'down' if status != 'up' else 'up',
        'description': device.configuration['description']}]}


def network_routes(profile: Profile, session: Session) -> dict:
    routes = []
    for interface in network_interfaces(profile, session)['interfaces']:
        if interface['status'] != 'up' or interface['protocol'] != 'up':
            continue
        address = ipaddress.ip_interface(f'{interface["address"]}/{interface["prefix_length"]}')
        routes += [{'code': 'C', 'prefix': str(address.network), 'interface': interface['name']},
                   {'code': 'L', 'prefix': str(address.ip) + '/32', 'interface': interface['name']}]
    return {'complete': True, 'routes': routes}


def path(profile: Profile, session: Session, name: str) -> str:
    if '\x00' in name or len(name.encode()) > 4096:
        raise ValueError('Invalid virtual path')
    if name == '~' or name.startswith('~/'):
        name = home(profile, session) + name[1:]
    return '/' + posixpath.normpath(posixpath.join(session.state.get('cwd', home(profile, session)), name)).lstrip('/')


def file_view(profile: Profile, session: Session) -> tuple[dict[str, bytes], set[str]]:
    files, dirs = virtual_files.view(profile, session)
    dirs |= {'/tmp', '/var/tmp', home(profile, session)}
    return files, dirs


def write(profile: Profile, session: Session, name: str, body: bytes) -> None:
    key = path(profile, session, name)
    files, dirs = file_view(profile, session)
    if key in dirs or posixpath.dirname(key) not in dirs:
        raise ValueError('Invalid virtual file destination')
    if not permitted(profile, session, key, 'write'):
        raise ValueError('Permission denied')
    updates = session.virtual_files | {key: body}
    if len(updates) + len(session.virtual_directories) + len(session.removed_files) > 128 or sum(map(len, updates.values())) > 65536:
        raise ValueError('Virtual filesystem capacity exceeded')
    session.virtual_files = updates
    session.removed_files.discard(key)


def permitted(profile: Profile, session: Session, key: str, operation: str) -> bool:
    uid = session.state.get('uid', '0' if session.username == 'root' else str(profile.identity.uid))
    if uid == '0':
        return True
    item = ensure(profile, session).metadata.get(key, {})
    mode = int(item.get('mode', '644'), 8)
    own = key.startswith(home(profile, session) + '/') or key.startswith('/tmp/') or key.startswith('/var/tmp/')
    bits = mode >> 6 if own else mode & 7
    if operation == 'write':
        return own and bool(bits & 2)
    return bool(bits & 4)


def prompt(profile: Profile, session: Session) -> bytes:
    device, spec = ensure(profile, session), pack(profile)
    if device.dialogue:
        return device.dialogue['prompt'].encode()
    host = device.hostname
    if spec.platform == 'ios':
        suffix = {'user': '>', 'privileged': '#', 'config': '(config)#', 'interface': '(config-if)#'}[device.mode]
        return (host + suffix + ' ').encode()
    cwd = session.state.get('cwd', home(profile, session))
    base = home(profile, session)
    display = '~' + cwd[len(base):] if cwd == base or cwd.startswith(base + '/') else cwd
    user = session.state.get('user', session.username)
    return f'{user}@{host}:{display}{"#" if user == "root" else "$"} '.encode()


def output(text: str = '', status: int = 0, error: str = '') -> Response:
    return SessionAction(body=text.encode(), stderr=error.encode(), exit_status=status, behavior='device')


def completion(profile: Profile, session: Session, text: str) -> list[str]:
    if pack(profile).platform == 'ios':
        return ios_candidates(ensure(profile, session).mode, text)
    if ' ' not in text:
        return [name for name in sorted(command_names(profile, session)) if name.startswith(text)]
    prefix, _, tail = text.rpartition(' ')
    files, dirs = file_view(profile, session)
    candidates = []
    parent = path(profile, session, tail or '.')
    for item in sorted(files.keys() | dirs):
        if item.startswith(parent) and item != parent:
            display = item if tail.startswith('/') else posixpath.relpath(item, session.state['cwd'])
            candidates.append(prefix + ' ' + display + ('/' if item in dirs else ''))
    return candidates[:64]


COMMANDS = {'hostname', 'whoami', 'id', 'uname', 'pwd', 'cd', 'ls', 'cat', 'touch', 'mkdir', 'rm',
            'echo', 'printf', 'wc', 'head', 'tail', 'grep', 'sort', 'env', 'export', 'which', 'command',
            'ps', 'kill', 'chmod', 'stat', 'cp', 'mv', 'true', 'false', 'help', 'history',
            'ifconfig', 'ip', 'netstat', 'ss', 'service', 'systemctl',
            'bash', 'sh', 'zsh', 'exit', 'logout', 'less', 'top', 'vi', 'device-menu'}


def command_names(profile: Profile, session: Session | None = None) -> set[str]:
    spec = pack(profile)
    names = COMMANDS - {'ifconfig', 'ip', 'ss', 'service', 'systemctl',
                        'less', 'top', 'vi', 'device-menu'}
    platform = {'linux': {'ip', 'ss', 'service', 'systemctl', 'free'},
                'macos': {'ifconfig', 'sw_vers'},
                'freebsd': {'ifconfig', 'service', 'freebsd-version'}, 'ios': set()}
    return (names | platform[spec.platform] | set(spec.applications) |
            {posixpath.basename(path) for path in virtual_files.executable_paths(profile, session)})


class Interpreter:
    """Parse a bounded grammar completely before dispatching virtual commands."""
    def __init__(self, runtime: Runtime, profile: Profile, session: Session):
        self.runtime, self.profile, self.session = runtime, profile, session
        self.device = ensure(profile, session)

    async def protected(self, interaction: Interaction) -> Response | None:
        from deceive import contracts
        from deceive.behaviors import matches
        import inspect
        if self.profile.contracts:
            result = await contracts.respond(self.runtime, self.profile, self.session, interaction)
            if result is not None:
                return result
        for spec in self.profile.behaviors:
            if spec.kind in {'identity', 'virtual_files'} or not matches(spec, interaction, self.session):
                continue
            handler = self.runtime.extensions.behaviors[spec.kind]
            result = (handler.respond if hasattr(handler, 'respond') else handler)(self.profile, spec, interaction, self.session)
            if inspect.isawaitable(result):
                result = await result
            if result is not None:
                result.behavior = spec.id
                return result
        return None

    async def respond(self, interaction: Interaction) -> Response:
        if self.device.dialogue:
            if self.device.dialogue['kind'] == 'model':
                result = await self.runtime._dispatch_direct(self.session, interaction)
                if not result.dialogue:
                    ensure(self.profile, self.session).dialogue = None
                return result
            if self.device.dialogue['kind'] == 'python':
                if interaction.command.strip() in {'exit()', 'quit()'}:
                    self.device.dialogue = None
                    return output()
                from deceive.device.python import run
                result = run(self.profile, self.session, interaction.command,
                    self.device.dialogue['imports'],
                    allow_model=bool(self.runtime.listeners[self.session.listener].provider))
                if result is not None:
                    return result
                return await self.runtime._dispatch_direct(
                    self.session, interaction, model_only=True)
            return self.dialogue(interaction.command)
        protected = await self.protected(interaction)
        if protected is not None:
            return protected
        if pack(self.profile).platform == 'ios':
            return await self.ios(interaction)
        text = interaction.command
        if '`' in text or '$(' in text:
            return output(status=2, error='sh: command substitution is unsupported\n')
        try:
            lexer = shlex.shlex(text, posix=False, punctuation_chars=';&|<>')
            lexer.whitespace_split = True
            lexer.commenters = ''
            tokens = list(lexer)
            if len(tokens) > 256:
                raise ValueError('Too many command tokens')
            # Validate all operators and operands before applying any effects.
            for i, token in enumerate(tokens):
                if token in {'&', '<<', ';;', '(', ')'} or (token[0:1] in ';&|<>' and token not in {';', '&&', '||', '|', '>', '>>', '<'}):
                    raise ValueError('Unsupported shell operator')
                if token in {'&&', '||', '|', '>', '>>', '<'} and (i == 0 or i == len(tokens) - 1 or tokens[i + 1] in {';', '&&', '||', '|', '>', '>>', '<'}):
                    raise ValueError('Missing command or redirect operand')
            groups, current, gate = [], [], ';'
            for token in tokens:
                if token in {';', '&&', '||'}:
                    if not current:
                        raise ValueError('Empty command')
                    groups.append((gate, current))
                    current, gate = [], token
                else:
                    current.append(token)
            if current:
                groups.append((gate, current))
            result, bodies, errors, chunks = output(), [], [], []
            for gate, group in groups:
                if (gate == '&&' and result.exit_status) or (gate == '||' and not result.exit_status):
                    continue
                stages, stage = [], []
                for token in group:
                    if token == '|':
                        stages.append(stage)
                        stage = []
                    else:
                        stage.append(token)
                stages.append(stage)
                stdin = b''
                for stage in stages:
                    result = await self.simple(stage, replace(interaction,
                        component=len(groups) > 1 or len(stages) > 1), stdin)
                    stdin = result.body
                    errors.append(result.stderr)
                    if result.stderr:
                        chunks.append(('stderr', result.stderr))
                    if result.close:
                        break
                bodies.append(result.body)
                if result.stderr:
                    chunks.pop()
                if result.body:
                    chunks.append(('stdout', result.body))
                if result.stderr:
                    chunks.append(('stderr', result.stderr))
                if result.close:
                    break
            if not groups:
                return output(status=self.session.last_exit_status)
            return replace(result, body=b''.join(bodies), stderr=b''.join(errors), chunks=chunks)
        except ValueError as exc:
            return output(status=2, error=f'sh: {exc}\n')

    def expand(self, token: str) -> str:
        if token.startswith("'") and token.endswith("'"):
            return token[1:-1]
        value = token[1:-1] if token.startswith('"') and token.endswith('"') else token
        environment = {'HOME': home(self.profile, self.session), 'USER': self.session.username,
                       'SHELL': '/bin/' + self.device.interpreter,
                       '?': str(self.session.last_exit_status)}
        environment.update({k[4:]: v for k, v in self.session.state.items() if k.startswith('env:')})
        value = re.sub(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*|\?))',
                       lambda m: environment.get(m[1] or m[2], ''), value)
        return home(self.profile, self.session) + value[1:] if value == '~' or value.startswith('~/') else value

    async def simple(self, tokens: list[str], interaction: Interaction, stdin: bytes) -> Response:
        if not tokens:
            return output(status=2, error='sh: empty command\n')
        redirect, target, words = None, None, []
        for i, token in enumerate(tokens):
            if token in {'>', '>>', '<'}:
                if redirect is not None or i != len(tokens) - 2:
                    raise ValueError('Only one trailing redirection is supported')
                redirect, target = token, self.expand(tokens[i + 1])
                break
            value = self.expand(token)
            if not token.startswith(("'", '"')) and any(c in value for c in '*?['):
                files, dirs = file_view(self.profile, self.session)
                matches = sorted(item for item in files.keys() | dirs
                                 if fnmatch.fnmatchcase(item, path(self.profile,self.session,value)))
                words.extend(matches or [value])
            else:
                words.append(value)
        if not words:
            raise ValueError('Missing command')
        name, args = posixpath.basename(words[0]), words[1:]
        installed = virtual_files.executable_paths(self.profile, self.session)
        if words[0].startswith('/') and installed:
            files, _ = file_view(self.profile, self.session)
            if words[0] not in files:
                if not self.runtime.listeners[self.session.listener].provider:
                    return output(status=127, error=f'{words[0]}: No such file or directory\n')
            if words[0] not in installed:
                if words[0] in files:
                    return output(status=126, error=f'{words[0]}: Permission denied\n')
        if redirect == '<':
            key = path(self.profile, self.session, target)
            files, _ = file_view(self.profile, self.session)
            if key not in files or not permitted(self.profile, self.session, key, 'read'):
                return output(status=1, error=f'{target}: unavailable\n')
            stdin = files[key]
        translated = replace(interaction, command=shlex.join(words), raw_input=None)
        protected = await self.protected(translated)
        result = protected if protected is not None else await self.command(name, args, translated, stdin)
        self.session.last_exit_status = result.exit_status
        self.session.state.update(result.transition)
        result.transition = {}
        if redirect in {'>', '>>'} and not result.close:
            files, _ = file_view(self.profile, self.session)
            content = (files.get(path(self.profile, self.session, target), b'') if redirect == '>>' else b'') + result.body
            write(self.profile, self.session, target, content)
            result.body = b''
        return result

    async def command(self, name: str, args: list[str], interaction: Interaction, stdin: bytes) -> Response:
        profile, session, device = self.profile, self.session, self.device
        spec = pack(profile)
        if name in {'exit', 'logout'} and device.stack:
            if len(args) > 1 or (args and (not args[0].isascii() or not args[0].isdigit()
                                         or len(args[0]) > 3 or int(args[0]) > 255)):
                return output(status=2, error='exit: invalid status\n')
            status = int(args[0]) if args else session.last_exit_status
            frame = device.stack.pop()
            device.interpreter = frame.interpreter
            session.state['cwd'] = frame.cwd
            session.state = {k: v for k, v in session.state.items() if not k.startswith('env:')} | frame.environment
            return output(status=status)
        if name in {'bash', 'sh', 'zsh'} and not args and interaction.interactive:
            if len(device.stack) >= self.runtime.limits.application_depth:
                return output(status=1, error='Maximum interpreter depth reached\n')
            device.stack.append(Frame(device.interpreter, session.state['cwd'], {k: v for k, v in session.state.items() if k.startswith('env:')}))
            device.interpreter = name
            return output()
        if name in {'python', 'python3'}:
            if not any(posixpath.basename(item) == name
                       for item in virtual_files.executable_paths(profile, session)):
                return await self.runtime._dispatch_direct(session, interaction)
            from deceive.device.python import BANNER, VERSION, run
            if args in (['-V'], ['--version']):
                return output(VERSION + '\n')
            if len(args) == 2 and args[0] == '-c':
                result = run(profile, session, args[1], [],
                    allow_model=bool(self.runtime.listeners[session.listener].provider))
                return (result if result is not None else
                        await self.runtime._dispatch_direct(session, interaction, model_only=True))
            if args:
                return output(status=2, error=f'{name}: unsupported invocation\n')
            if interaction.interactive:
                device.dialogue = {'kind': 'python', 'prompt': '>>> ', 'imports': []}
                return output(BANNER)
            return output()
        if name in {'less', 'top', 'vi', 'device-menu'}:
            if name not in spec.applications:
                return output(status=127, error=f'{name}: command not found\n')
            if not interaction.interactive:
                return output(status=1, error=f'{name}: interactive terminal required\n')
            from deceive.device.apps import Application
            if name == 'less' and not args and stdin:
                if len(stdin) > 65536:
                    raise ValueError('Pager capacity exceeded')
                device.application = Application('less', '[stdin]', stdin.decode('utf-8', 'replace'))
            else:
                device.application = Application.open(name, args, profile, session)
            return output()
        if name == 'hostname':
            if args:
                if len(args) != 1 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}', args[0]):
                    return output(status=1, error='hostname: invalid name\n')
                device.hostname = args[0]
                session.virtual_files['/etc/hostname'] = (args[0] + '\n').encode()
                return output()
            return output(device.hostname + '\n')
        if name == 'uname':
            system = {'linux': 'Linux', 'macos': 'Darwin', 'freebsd': 'FreeBSD'}[spec.platform]
            selected = set()
            for argument in args or ['-s']:
                if spec.platform == 'linux':
                    argument = {'--all': '-a', '--kernel-name': '-s', '--nodename': '-n',
                                '--kernel-release': '-r', '--machine': '-m'}.get(argument, argument)
                if not argument.startswith('-') or argument == '-':
                    return output(status=1, error=f'uname: unexpected operand: {argument}\n')
                for flag in argument[1:]:
                    if flag not in 'asnrm':
                        return output(status=1, error=f'uname: invalid option -- {flag}\n')
                    selected.update('snrm' if flag == 'a' else flag)
            facts = {'s': system, 'n': device.hostname, 'r': profile.identity.kernel,
                     'm': profile.identity.architecture}
            return output(' '.join(facts[flag] for flag in 'snrm' if flag in selected) + '\n')
        if name == 'sw_vers' and spec.platform == 'macos':
            return output('ProductName:\tmacOS\nProductVersion:\t14.0\nBuildVersion:\t23A344\n')
        if name == 'freebsd-version' and spec.platform == 'freebsd':
            return output('14.0-RELEASE\n')
        if name in {'help', 'which', 'command'}:
            if name == 'help':
                return output('Virtual commands: ' + ' '.join(sorted(command_names(profile, session))) + '\n')
            wanted = args[-1] if args else ''
            installed = [item for item in virtual_files.executable_paths(profile, session)
                         if posixpath.basename(item) == wanted]
            if installed:
                return output(installed[0] + '\n')
            if virtual_files.executable_paths(profile):
                if self.runtime.listeners[session.listener].provider:
                    return await self.runtime._dispatch_direct(session, interaction, model_only=True)
                return output(status=1)
            if profile.command_environment:
                from deceive.commands import program_names
                program = program_names(profile).get(wanted)
                if program:
                    return output(program.path + '\n')
            return output('/usr/bin/' + wanted + '\n') if wanted in command_names(profile) else output(status=1)
        if name in {'true', 'false'}:
            return output(status=int(name == 'false'))
        if name == 'echo':
            newline = not (args and args[0] == '-n')
            return output(' '.join(args if newline else args[1:]) + ('\n' if newline else ''))
        if name == 'env':
            values = {'HOME': home(profile, session), 'USER': session.username, 'SHELL': '/bin/' + device.interpreter}
            values.update({k[4:]: v for k, v in session.state.items() if k.startswith('env:')})
            return output(''.join(k + '=' + v + '\n' for k, v in sorted(values.items())))
        if name == 'export' or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', name):
            assignments = args if name == 'export' else [name] + args
            if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', item) for item in assignments):
                return output(status=1, error='export: invalid assignment\n')
            for item in assignments:
                key, value = item.split('=', 1)
                session.state['env:' + key] = value
            return output()
        if name == 'ps':
            if args in (['aux'], ['-aux']):
                inventory = resources(profile, self.session)
                return output('USER       PID %CPU %MEM    VSZ   RSS STAT COMMAND\n' + ''.join(
                    f'{p["user"]:<8} {p["pid"]:5} {p["cpu_percent"]:4.1f} '
                    f'{100 * p["resident_kib"] / inventory["memory_total_kib"]:4.1f} '
                    f'{p["virtual_kib"]:6} {p["resident_kib"]:5} {p["state"]:4} {p["command"]}\n'
                    for p in inventory['processes']))
            return output('  PID COMMAND\n' + ''.join(f'{pid:5} {command}\n' for pid, command in sorted(device.processes.items())))
        if name == 'free' and spec.platform == 'linux' and args == ['-m']:
            inventory = resources(profile, self.session)
            return output('               total        used        free\n' +
                f'Mem:       {inventory["memory_total_kib"] // 1024:9} '
                f'{inventory["memory_used_kib"] // 1024:11} {inventory["memory_free_kib"] // 1024:11}\n' +
                f'Swap:      {inventory["swap_total_kib"] // 1024:9}           0 '
                f'{inventory["swap_total_kib"] // 1024:11}\n')
        if name == 'ifconfig' and spec.platform in {'macos', 'freebsd'}:
            interface = 'en0' if spec.platform == 'macos' else 'em0'
            return output(f'{interface}: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n')
        if name == 'ip' and spec.platform == 'linux' and args in (['addr'], ['address'], ['addr', 'show']):
            return output('2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.0.2.10/24 scope global eth0\n')
        if name == 'netstat' and args == ['-rn']:
            return output('Routing tables\nDestination Gateway\ndefault 192.0.2.1\n')
        if name == 'ss' and spec.platform == 'linux' and args == ['-lnt']:
            return output('State Recv-Q Send-Q Local Address:Port Peer Address:Port\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n')
        if name in {'service', 'systemctl'} and any(a in {'ssh', 'sshd'} for a in args):
            return output('sshd is running\n' if spec.platform == 'freebsd' else
                          'sshd.service - SSH server\n   Active: active (running)\n')
        if name == 'kill':
            if len(args) != 1 or not args[0].isdigit() or int(args[0]) not in device.processes:
                return output(status=1, error='kill: no such process\n')
            pid = int(args[0])
            if pid in {1, 120}:
                return output(status=1, error='kill: operation not permitted\n')
            del device.processes[pid]
            return output()
        files, dirs = file_view(profile, session)
        if name in {'cp', 'mv'} and len(args) == 2:
            source, dest = (path(profile, session, a) for a in args)
            if source not in files or not permitted(profile, session, source, 'read'):
                return output(status=1, error=f'{name}: source unavailable\n')
            if name == 'mv' and not permitted(profile, session, source, 'write'):
                raise ValueError('Permission denied')
            write(profile, session, dest, files[source])
            if name == 'mv':
                if not permitted(profile, session, source, 'write'):
                    raise ValueError('Permission denied')
                session.virtual_files.pop(source, None)
                session.removed_files.add(source)
            return output()
        if name in {'chmod', 'stat'} and args:
            key = path(profile, session, args[-1])
            if key not in files:
                return output(status=1, error=f'{name}: no such file\n')
            if name == 'chmod':
                if len(args) != 2 or not re.fullmatch(r'[0-7]{3}', args[0]):
                    return output(status=1, error='chmod: expected octal mode\n')
                if not key.startswith(home(profile, session) + '/') and not key.startswith('/tmp/'):
                    return output(status=1, error='chmod: operation not permitted\n')
                device.metadata[key] = {'mode': args[0]}
                return output()
            return output(f'File: {key}\nSize: {len(files[key])}\nMode: {device.metadata.get(key, {}).get("mode", "644")}\n')
        if name in {'cat', 'head', 'tail', 'grep', 'sort', 'wc'}:
            selected = []
            diagnostics = []
            patterns = args
            if name in {'head', 'tail'} and args[:1] == ['-n']:
                if len(args) < 2 or not args[1].isdigit():
                    return output(status=1, error='Invalid line count\n')
                count, patterns = min(int(args[1]), 65536), args[2:]
            else:
                count = 10
            if name == 'grep':
                patterns = args[1:]
            if name == 'wc':
                patterns = [a for a in args if not a.startswith('-')]
            for arg in patterns:
                key = path(profile, session, arg)
                if key not in files:
                    if name == 'cat':
                        diagnostics.append(f'cat: {arg}: No such file or directory\n')
                        continue
                    return output(status=1, error=f'{name}: {arg}: No such file or directory\n')
                if not permitted(profile, session, key, 'read'):
                    if name == 'cat':
                        diagnostics.append(f'cat: {arg}: Permission denied\n')
                        continue
                    return output(status=1, error=f'{name}: {arg}: Permission denied\n')
                selected.append(files[key])
            content = b''.join(selected) if patterns else stdin
            if name == 'cat':
                return Response(body=content, stderr=''.join(diagnostics).encode(),
                                exit_status=int(bool(diagnostics)), behavior='device/cat')
            lines = content.splitlines(keepends=True)
            if name in {'head', 'tail'}:
                return Response(body=b''.join(lines[:count] if name == 'head' else lines[-count:] if count else []), behavior='device/text')
            if name == 'grep':
                if not args:
                    return output(status=2, error='grep: pattern required\n')
                matches = [line for line in lines if args[0].encode() in line]
                return Response(body=b''.join(matches), exit_status=0 if matches else 1, behavior='device/grep')
            if name == 'sort':
                return Response(body=b''.join(sorted(lines)), behavior='device/sort')
            value = len(content) if '-c' in args or '--bytes' in args else len(lines) if '-l' in args else len(content.split())
            return output(f'{value}' + (' ' + patterns[0] if patterns else '') + '\n')
        # Existing contracts and accepted behavior remain the authority for other primitives.
        result = await self.runtime._dispatch_direct(session, interaction)
        return result

    def dialogue(self, text: str) -> Response:
        question = self.device.dialogue
        self.device.dialogue = None
        if question['kind'] == 'enable':
            if text == pack(self.profile).enable_password:
                self.device.mode = 'privileged'
                return output()
            return output('% Access denied\n', 1)
        if question['kind'] == 'confirm':
            if text.lower() in {'y', 'yes', ''}:
                self.device.startup = dict(self.device.configuration) | {'hostname': self.device.hostname}
                return output('[OK]\n')
            return output('Cancelled\n')
        return output()

    async def ios(self, interaction: Interaction) -> Response:
        text = interaction.command
        words = text.split()
        if not words:
            return output()
        candidates = ios_candidates(self.device.mode, '')
        # Resolve each keyword against declared forms, preserving argument words.
        forms = [form.split() for form in candidates]
        possibilities = [form for form in forms if len(words) <= len(form) and all(f.startswith(w) for f, w in zip(form, words))]
        exact = [form for form in possibilities if len(form) == len(words)]
        if len(exact) == 1:
            words = exact[0]
        elif len(exact) > 1:
            return output('% Ambiguous command\n', 1)
        command = ' '.join(words)
        device = self.device
        if command in {'exit', 'logout'}:
            if device.mode == 'interface': device.mode = 'config'
            elif device.mode == 'config': device.mode = 'privileged'
            else: return Response(close=True, behavior='device/ios')
            return output()
        if command == 'end':
            device.mode = 'privileged'
            return output()
        if command == 'enable' and device.mode == 'user':
            device.dialogue = {'kind': 'enable', 'prompt': 'Password: '}
            return output()
        if command == 'disable':
            device.mode = 'user'
            return output()
        if command == 'configure terminal' and device.mode == 'privileged':
            device.mode = 'config'
            return output('Enter configuration commands, one per line. End with CNTL/Z.\n')
        if command.startswith('interface ') and device.mode == 'config':
            device.configuration['interface'] = command.split(' ', 1)[1]
            device.mode = 'interface'
            return output()
        if command.startswith('hostname ') and device.mode == 'config':
            value = command.split(' ', 1)[1]
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}', value):
                return output('% Invalid hostname\n', 1)
            device.hostname = value
            return output()
        if command.startswith('description ') and device.mode == 'interface':
            device.configuration['description'] = command.split(' ', 1)[1]
            return output()
        if command in {'shutdown', 'no shutdown'} and device.mode == 'interface':
            device.configuration['shutdown'] = 'yes' if command == 'shutdown' else 'no'
            return output()
        if command == 'show version':
            return output(f'Cisco IOS XE Software, Version 17.9\n{device.hostname} uptime is 1 day\n')
        if command == 'show ip route':
            routes = network_routes(self.profile, self.session)['routes']
            return output('Codes: C - connected, L - local\nGateway of last resort is not set\n\n' +
                ''.join(f'{route["code"]}    {route["prefix"]} is directly connected, {route["interface"]}\n'
                        for route in routes))
        if command in {'show running-config', 'show startup-config'} and device.mode == 'privileged':
            config = device.configuration if command == 'show running-config' else device.startup
            return output(f'hostname {config.get("hostname", device.hostname)}\ninterface {config.get("interface", "GigabitEthernet0/0")}\n description {config.get("description", "uplink")}\n ip address 192.0.2.10 255.255.255.0\n {"shutdown" if config.get("shutdown") == "yes" else "no shutdown"}\nend\n')
        if command in {'show interfaces', 'show ip interface brief'}:
            interfaces = network_interfaces(self.profile, self.session)['interfaces']
            if command == 'show ip interface brief':
                return output('Interface              IP-Address      OK? Method Status                Protocol\n' + ''.join(
                    f'{item["name"]:<22} {item["address"]:<15} YES manual {item["status"]:<21} {item["protocol"]}\n'
                    for item in interfaces))
            return output(''.join(f'{item["name"]} is {item["status"]}, line protocol is {item["protocol"]}\n'
                f'  Description: {item["description"]}\n' for item in interfaces))
        if command == 'copy running-config startup-config' and device.mode == 'privileged':
            device.dialogue = {'kind': 'confirm', 'prompt': 'Destination filename [startup-config]? '}
            return output()
        if command.startswith('terminal length ') and device.mode in {'user', 'privileged'}:
            value = command.removeprefix('terminal length ')
            if not value.isascii() or not value.isdigit() or not 0 <= int(value) <= 512:
                return output('% Invalid terminal length (0-512)\n', 1)
            self.session.state['terminal_length'] = str(int(value))
            return output()
        if command.endswith('?'):
            return output('\n'.join(ios_candidates(device.mode, command[:-1])) + '\n')
        if possibilities:
            return output('% Incomplete command\n', 1)
        if command.startswith('show ') and self.runtime.listeners[self.session.listener].provider:
            return await self.runtime._dispatch_direct(self.session, interaction)
        forms = [form.split() for form in ios_candidates(device.mode, '')]
        offset = 0
        for index, token in enumerate(re.finditer(r'\S+', text)):
            forms = [form for form in forms if len(form) > index and form[index].startswith(token.group().lower())]
            if not forms:
                offset = token.start()
                break
        prefix = len(prompt(self.profile, self.session)) if interaction.interactive else 0
        echoed = '' if interaction.interactive else text + '\n'
        return output(echoed + ' ' * (prefix + offset) + "^\n% Invalid input detected at '^' marker.\n", 1)


def ios_candidates(mode: str, text: str) -> list[str]:
    forms = ['show version', 'show interfaces', 'show ip interface brief', 'show ip route', 'exit', 'logout', 'enable', 'terminal length 0']
    if mode == 'privileged':
        forms += ['show running-config', 'show startup-config', 'configure terminal', 'copy running-config startup-config', 'disable']
    if mode == 'config': forms = ['hostname', 'interface', 'end', 'exit']
    if mode == 'interface': forms = ['description', 'shutdown', 'no shutdown', 'end', 'exit']
    return [form for form in forms if form.startswith(text)]


def apply_effects(profile: Profile, session: Session, result: Response,
                  interaction: Interaction | None = None) -> None:
    """Validate a model proposal on the staged session; callers commit only after success."""
    from deceive.device.terminal import safe_text
    device = ensure(profile, session)
    effects = result.effects
    has_executable_inventory = bool(virtual_files.executable_paths(profile))
    known_before = command_names(profile, session) if has_executable_inventory else set()

    def register_executable(name: str) -> None:
        if not re.fullmatch(r'/(?:bin|usr/bin|usr/sbin)/[A-Za-z0-9_.+-]+', name):
            raise ValueError('Model requested invalid virtual executable path')
        if name in profile.files or name in session.virtual_files:
            raise ValueError('Model executable conflicts with virtual file')
        if name in device.executable_removals:
            device.executable_removals.remove(name)
        if name not in virtual_files.executable_paths(profile, session):
            if len(device.executable_additions) >= 32:
                raise ValueError('Virtual executable inventory capacity exceeded')
            device.executable_additions.append(name)

    for name in effects.get('add_executables', []):
        register_executable(name)
    if interaction is not None and has_executable_inventory and not (
            device.dialogue and device.dialogue.get('kind') == 'python'):
        try:
            words = shlex.split(interaction.command)
        except ValueError:
            words = []
        discovery = (len(words) == 2 and words[0] == 'which') or (
            len(words) == 3 and words[:2] == ['command', '-v'])
        if discovery and result.exit_status == 0:
            claimed = result.body.decode('utf-8', 'strict').strip()
            if (not re.fullmatch(r'/(?:bin|usr/bin|usr/sbin)/[A-Za-z0-9_.+-]+', claimed)
                    or posixpath.basename(claimed) != words[-1]):
                raise ValueError('Model discovery conflicts with virtual executable inventory')
            register_executable(claimed)
        elif (words and result.exit_status == 0 and not result.close and
              '/' not in words[0] and words[0] not in known_before and
              re.fullmatch(r'[A-Za-z0-9_.+-]+', words[0])):
            if not any(posixpath.basename(item) == words[0]
                       for item in virtual_files.executable_paths(profile, session)):
                register_executable('/usr/bin/' + words[0])
    for name in effects.get('remove_executables', []):
        if name not in virtual_files.executable_paths(profile, session):
            raise ValueError('Model requested removal of unknown virtual executable')
        if name not in device.executable_additions:
            raise ValueError('Model cannot remove a baseline virtual executable')
        if name not in device.executable_removals:
            if len(device.executable_removals) >= 32:
                raise ValueError('Virtual executable inventory capacity exceeded')
            device.executable_removals.append(name)
    for name, content in effects.get('write_files', {}).items():
        write(profile, session, name, content.encode())
    files, dirs = file_view(profile, session)
    for name in effects.get('remove_files', []):
        key = path(profile, session, name)
        if key not in files or not permitted(profile, session, key, 'write'):
            raise ValueError('Model requested forbidden removal')
        session.virtual_files.pop(key, None)
        session.removed_files.add(key)
    for key, value in effects.get('configuration', {}).items():
        if key == 'hostname':
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,62}', value):
                raise ValueError('Invalid effective hostname')
            device.hostname = value
            session.virtual_files['/etc/hostname'] = (value + '\n').encode()
        elif key == 'description' and len(value.encode()) <= 256 and safe_text(value) == value:
            device.configuration[key] = value
        else:
            raise ValueError('Model requested forbidden configuration')
    if effects.get('cwd') is not None:
        cwd = path(profile, session, effects['cwd'])
        if cwd not in dirs:
            raise ValueError('Model requested nonexistent cwd')
        session.state['cwd'] = cwd
    if result.dialogue:
        if device.dialogue and device.dialogue.get('kind') == 'python':
            raise ValueError('Model cannot replace active Python prompt')
        if safe_text(result.dialogue['prompt']) != result.dialogue['prompt']:
            raise ValueError('Invalid dialogue prompt')
        device.dialogue = {'kind': 'model', 'prompt': result.dialogue['prompt'],
                           'echo': result.dialogue['echo']}
