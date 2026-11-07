"""Small, bounded virtual file commands. Never opens paths or executes commands."""
from __future__ import annotations

import posixpath
import re
import shlex

from deceive.interaction import Interaction, Response, Session
from deceive.models import Behavior, Profile

MAX_NODES = 128
MAX_BYTES = 65536
EXECUTABLE_STUB = b'\x7fELF\x02\x01\x01\x00'


def enabled(profile: Profile) -> bool:
    return any(b.kind == 'virtual_files' for b in profile.behaviors)


def view(profile: Profile, session: Session) -> tuple[dict[str, bytes], set[str]]:
    files = {p: text.encode() for p, text in profile.files.items() if p not in session.removed_files}
    for executable in executable_paths(profile, session):
        if executable not in session.removed_files:
            files.setdefault(executable, EXECUTABLE_STUB)
    files.update(session.virtual_files)
    from deceive.device.engine import home as device_home
    home = device_home(profile, session)
    directories = {'/', '/home', home} | session.virtual_directories
    for behavior in profile.behaviors:
        if behavior.kind == 'virtual_files':
            directories.update(behavior.options.get('directories', []))
    for path in list(files) + list(directories):
        while path not in {'/', '//', ''}:
            path = posixpath.dirname(path)
            directories.add(path)
    return files, directories


def executable_paths(profile: Profile, session: Session | None = None) -> list[str]:
    baseline = [path for behavior in profile.behaviors if behavior.kind == 'virtual_files'
                for path in behavior.options.get('executables', [])]
    device = getattr(session, 'device', None)
    additions = getattr(device, 'executable_additions', [])
    removals = set(getattr(device, 'executable_removals', []))
    return list(dict.fromkeys(path for path in baseline + additions if path not in removals))


def validate(spec: Behavior, profile: Profile | None) -> None:
    if profile is not None and profile.protocol != 'ssh':
        raise ValueError('Virtual files require SSH')
    if set(spec.options) - {'directories', 'listing_time', 'executables'}:
        raise ValueError('Unknown virtual_files option')
    listing_time = spec.options.get('listing_time', 'Jan 15 09:00')
    if not isinstance(listing_time, str) or not re.fullmatch(
        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-3][0-9] '
        r'(?:[0-2][0-9]:[0-5][0-9]| [0-9]{4})', listing_time
    ):
        raise ValueError('Virtual listing_time must use an ls-style month, day and time or year')
    directories = spec.options.get('directories', [])
    if not isinstance(directories, list) or len(directories) > MAX_NODES or any(
        not isinstance(p, str) or not p.startswith('/') or '\x00' in p or len(p.encode()) > 4096
        or p.startswith('//') or posixpath.normpath(p) != p for p in directories
    ):
        raise ValueError('Virtual directories must be bounded, normalized absolute paths')
    executables = spec.options.get('executables', [])
    if not isinstance(executables, list) or len(executables) > MAX_NODES or any(
        not isinstance(p, str) or not re.fullmatch(r'/(?:bin|usr/bin|usr/sbin)/[A-Za-z0-9_.+-]+', p)
        for p in executables
    ) or len(set(executables)) != len(executables):
        raise ValueError('Virtual executables must be unique, bounded /bin or /usr/bin paths')
    if profile is not None and any(p in profile.files for p in executables):
        raise ValueError('Virtual executables cannot replace profile files')
    if profile is not None and any(p.startswith('//') or '\x00' in p or
        posixpath.normpath(p) != p or len(p.encode()) > 4096 for p in profile.files):
        raise ValueError('Virtual file names must be bounded, normalized absolute paths')


def shell_name(profile: Profile, session: Session) -> str:
    """Use the simulated account's shell for diagnostics when it is declared."""
    account = profile.ssh_auth.accounts.get(session.username) if profile.ssh_auth else None
    return (posixpath.basename(account.shell) if account else
            profile.device.interpreter if profile.device else 'bash')


def respond(profile: Profile, spec: Behavior, interaction: Interaction,
            session: Session) -> Response | None:
    if interaction.protocol != 'ssh':
        return None
    shell = shell_name(profile, session)
    try:
        words = shlex.split(interaction.command)
    except ValueError:
        return Response(stderr=f'{shell}: syntax error\n'.encode(), exit_status=2)
    if words and words[0] in {'/usr/bin/wc', '/bin/wc'}:
        words[0] = 'wc'
    if words and words[0] in {'printf', '/usr/bin/printf', '/bin/printf'}:
        if (len(words) != 2 or words[1].startswith('-') or
            any(c in interaction.command for c in '\\$`;|&<>\r\n')):
            return None
        text, output, index = words[1], [], 0
        while index < len(text):
            if text[index] != '%':
                output.append(text[index])
                index += 1
            elif index + 1 == len(text):
                return Response(body=''.join(output).encode(),
                    stderr=b'printf: %: invalid conversion specification\n', exit_status=1)
            elif text[index + 1] == '%':
                output.append('%')
                index += 2
            else:
                return None
        return Response(body=''.join(output).encode())
    if words and words[0] == 'history' and len(words) == 1:
        if not interaction.interactive:
            return Response()
        commands = [m.content for m in session.history if m.role == 'user' and m.content.strip()]
        commands.append(interaction.command)
        first = max(1, session.input_count - len(commands) + 1)
        return Response(body=''.join(f'{n:5}  {command}\n'
            for n, command in enumerate(commands, first)).encode())
    if not words or words[0] not in {'cat', 'ls', 'cd', 'touch', 'mkdir', 'rm', 'echo', 'wc'}:
        return None
    files, directories = view(profile, session)
    from deceive.device.engine import home as device_home
    home = device_home(profile, session)
    cwd = session.state.get('cwd', home)

    def path(name: str) -> str:
        if '\x00' in name or len(name.encode()) > 4096:
            raise ValueError('Virtual path exceeds supported bounds')
        name = home + name[1:] if name == '~' or name.startswith('~/') else name
        return '/' + posixpath.normpath(posixpath.join(cwd, name)).lstrip('/')

    def error(command: str, name: str, reason: str, status: int = 1) -> Response:
        return Response(stderr=f'{command}: {name}: {reason}\n'.encode(), exit_status=status)

    def protected_binary_path(key: str) -> bool:
        return key.startswith(('/bin/', '/usr/bin/', '/usr/sbin/'))

    def capacity(new_files: dict[str, bytes], new_dirs: set[str], removed: set[str]) -> bool:
        return (len(new_files) + len(new_dirs) + len(removed) <= MAX_NODES
                and sum(len(v) for v in new_files.values()) <= MAX_BYTES)

    command, args = words[0], words[1:]
    listing_time = spec.options.get('listing_time', 'Jan 15 09:00')
    # Complex shell grammar stays with generative fallback; this parser never evaluates it.
    if any(token in {';', '&&', '||', '|', '<', '2>', '>&2'} for token in args):
        return None
    if command == 'wc' and len(args) == 2 and args[0] in {'-c', '--bytes'} and not args[1].startswith('-'):
        key = path(args[1])
        if key not in files:
            reason = 'Is a directory' if key in directories else 'No such file or directory'
            return error('wc', args[1], reason)
        return Response(body=f'{len(files[key])} {args[1]}\n'.encode())
    if command == 'cat' and args and all(not a.startswith('-') for a in args):
        output, diagnostics = bytearray(), bytearray()
        for name in args:
            key = path(name)
            if key in files:
                output.extend(files[key])
            else:
                reason = 'Is a directory' if key in directories else 'No such file or directory'
                diagnostics.extend(error('cat', name, reason).stderr)
        return Response(body=bytes(output), stderr=bytes(diagnostics), exit_status=int(bool(diagnostics)))
    if command == 'cd' and len(args) <= 1:
        name = args[0] if args else home
        key = path(name)
        if key not in directories:
            return error(f'{shell}: cd', name, 'Not a directory' if key in files else 'No such file or directory')
        return Response(transition={'cwd': key})
    if command == 'ls':
        flags = ''.join(a[1:] for a in args if a.startswith('-'))
        names = [a for a in args if not a.startswith('-')]
        if set(flags) - set('laA1dh') or len(names) > 1:
            return None
        name = names[0] if names else '.'
        key = path(name)
        if key not in files and key not in directories:
            return error('ls: cannot access', "'" + name + "'", 'No such file or directory', 2)
        listing = []
        if key in files or 'd' in flags:
            listing.append((name, key))
        else:
            children = sorted({p for p in files.keys() | directories if p != key and posixpath.dirname(p) == key})
            listing = [(posixpath.basename(p), p) for p in children
                       if 'a' in flags or 'A' in flags or not posixpath.basename(p).startswith('.')]
            if 'a' in flags:
                listing = [('.', key), ('..', posixpath.dirname(key))] + listing
        rows = []
        for display, item in listing:
            if 'l' in flags:
                directory = item in directories
                size = 4096 if directory else len(files[item])
                private = item in session.virtual_files or item in session.virtual_directories
                owner = session.state.get('user', session.username) if private or item.startswith(home + '/') else 'root'
                if item == home:
                    owner = session.username
                mode = 'drwxr-xr-x' if directory else '-rw-r--r--'
                metadata = getattr(session.device, 'metadata', {}).get(item, {})
                if not directory and 'mode' in metadata:
                    bits = int(metadata['mode'], 8)
                    mode = '-' + ''.join(letter if bits & (1 << (8 - index)) else '-'
                                         for index, letter in enumerate('rwxrwxrwx'))
                elif item in executable_paths(profile, session):
                    mode = '-rwxr-xr-x'
                if item in {'/tmp', '/var/tmp'}:
                    mode = 'drwxrwxrwt'
                links = 2 + sum(posixpath.dirname(p) == item and p != item for p in directories) if directory else 1
                rows.append(f'{mode} {links} {owner} {owner} {size} {listing_time} {display}')
            else:
                rows.append(display)
        if 'l' in flags and key in directories and 'd' not in flags:
            blocks = sum(((4096 if item in directories else len(files[item])) + 4095) // 4096 * 4
                         for _, item in listing)
            rows.insert(0, f'total {blocks}')
        return Response(body=(''.join(row + '\n' for row in rows)).encode())
    if command in {'touch', 'mkdir', 'rm'} and args and all(not a.startswith('-') for a in args):
        updates, dirs, removed = dict(session.virtual_files), set(session.virtual_directories), set(session.removed_files)
        for name in args:
            key = path(name)
            if protected_binary_path(key):
                return error(command, name, 'Permission denied')
            if command == 'rm':
                if key not in files:
                    return error('rm: cannot remove', "'" + name + "'", 'Is a directory' if key in directories else 'No such file or directory')
                updates.pop(key, None)
                removed.add(key)
            else:
                if posixpath.dirname(key) not in directories | dirs:
                    return error(command, name, 'No such file or directory')
                if command == 'mkdir':
                    if key in files or key in directories | dirs:
                        return error(command, name, 'File exists')
                    dirs.add(key)
                elif key not in directories:
                    updates[key] = files.get(key, b'')
                    removed.discard(key)
        if not capacity(updates, dirs, removed):
            return error(command, args[0], 'No space left on device')
        session.virtual_files, session.virtual_directories, session.removed_files = updates, dirs, removed
        return Response()
    if command == 'echo' and len(args) >= 2 and args[-2] in {'>', '>>'}:
        # Only literal echo redirection is supported. Expansions are not evaluated here.
        if any('$' in a or '`' in a or a in {'>', '>>'} for a in args[:-2]):
            return None
        key = path(args[-1])
        if protected_binary_path(key):
            return error(shell, args[-1], 'Permission denied')
        if key in directories:
            return error(shell, args[-1], 'Is a directory')
        if posixpath.dirname(key) not in directories:
            return error(shell, args[-1], 'No such file or directory')
        values = args[:-2]
        newline = not (values and values[0] == '-n')
        if not newline:
            values = values[1:]
        if values and values[0].startswith('-'):
            return None
        content = (' '.join(values) + ('\n' if newline else '')).encode()
        if args[-2] == '>>':
            content = files.get(key, b'') + content
        updates = session.virtual_files | {key: content}
        removed = session.removed_files - {key}
        if not capacity(updates, session.virtual_directories, removed):
            return error(shell, args[-1], 'No space left on device')
        session.virtual_files, session.removed_files = updates, removed
        return Response()
    return None
