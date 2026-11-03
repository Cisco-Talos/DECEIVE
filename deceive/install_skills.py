"""Offline installation and ownership-aware synchronization of bundled agent skills."""
from __future__ import annotations

import hashlib
from importlib import resources
from importlib.resources.abc import Traversable
from importlib.metadata import version
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
from urllib.parse import unquote, urlsplit
import uuid

import yaml

MANIFEST = '.deceive-skills.json'
NAME = re.compile(r'deceive(?:-[a-z0-9]+)*')


def bundle_root() -> Traversable:
    bundled = resources.files('deceive').joinpath('_skill_assets')
    if bundled.is_dir():
        return bundled
    checkout = Path(__file__).resolve().parent.parent
    if (checkout / 'skills/deceive/SKILL.md').is_file():
        return checkout
    raise ValueError('Bundled skills are missing; reinstall the DECEIVE wheel')


def walk(root: Traversable, prefix: str = '') -> dict[str, bytes]:
    output = {}
    for child in sorted(root.iterdir(), key=lambda p: p.name):
        if (child.name.startswith('.') or child.name == '__pycache__'
            or PurePosixPath(child.name).suffix in {'.pyc', '.key', '.pem'}
            or child.name.endswith('_host_key')):
            continue
        if getattr(child, 'is_symlink', lambda: False)():
            raise ValueError('Bundled skill assets cannot contain symlinks')
        name = prefix + child.name
        if child.is_dir():
            output.update(walk(child, name + '/'))
        elif child.is_file():
            output[name] = child.read_bytes()
    return output


def payloads() -> dict[str, bytes]:
    root = bundle_root()
    source = {'skills/' + k: v for k, v in walk(root.joinpath('skills')).items()}
    for folder in ('docs', 'examples'):
        directory = root.joinpath(folder)
        if directory.is_dir():
            source.update({folder + '/' + k: v for k, v in walk(directory).items()
                           if (folder == 'docs' and k.endswith('.md') and '/' not in k) or
                           (folder == 'examples' and k.endswith('.yaml') and
                            (len(PurePosixPath(k).parts) == 1 or
                             PurePosixPath(k).parent == PurePosixPath('profiles')))})
    for name in ('README.md', 'LICENSE'):
        if root.joinpath(name).is_file():
            source[name] = root.joinpath(name).read_bytes()
    names = sorted({k.split('/')[1] for k in source if re.fullmatch(r'skills/[^/]+/SKILL.md', k)})
    if not names:
        raise ValueError('No bundled DECEIVE skills found')
    for name in names:
        if not NAME.fullmatch(name):
            raise ValueError('Invalid bundled DECEIVE skill name')
        text = source[f'skills/{name}/SKILL.md'].decode()
        frontmatter = text.split('---', 2)
        try:
            metadata = yaml.safe_load(frontmatter[1]) if len(frontmatter) == 3 else None
        except yaml.YAMLError:
            raise ValueError(f'Invalid skill frontmatter: {name}') from None
        if (not isinstance(metadata, dict) or metadata.get('name') != name
            or not isinstance(metadata.get('description'), str) or not metadata['description'].strip()):
            raise ValueError(f'Invalid skill frontmatter: {name}')

    def destination(key: str, name: str) -> str:
        return key.removeprefix('skills/') if key.startswith('skills/') else name + '/references/' + key

    output = {}
    for name in names:
        for key, body in source.items():
            if key.startswith('skills/') and not key.startswith(f'skills/{name}/'):
                continue
            target = destination(key, name)
            if key.endswith('.md'):
                text = body.decode('utf-8')

                def link(match: re.Match[str]) -> str:
                    address = urlsplit(match[2])
                    if address.scheme or address.netloc or not address.path:
                        return match[0]
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(key), unquote(address.path)))
                    if resolved not in source:
                        return match[0]
                    relative = posixpath.relpath(destination(resolved, name), posixpath.dirname(target))
                    suffix = ('?' + address.query if address.query else '') + ('#' + address.fragment if address.fragment else '')
                    return f'[{match[1]}]({relative}{suffix})'

                text = re.sub(r'\[([^\]\n]+)\]\(([^)\n]+)\)', link, text)
                # Repository-root reading references also appear as inline code in canonical skills.
                if key.startswith('skills/'):
                    def inline(match: re.Match[str]) -> str:
                        ref = match[1]
                        if ref not in source or not ref.startswith(('docs/', 'examples/')):
                            return match[0]
                        relative = posixpath.relpath(destination(ref, name), posixpath.dirname(target))
                        return f'[{ref}]({relative})'
                    text = re.sub(r'`([^`\n]+)`', inline, text)
                body = text.encode()
            output[target] = body
    return output


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def safe(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if (not parts or PurePosixPath(relative).is_absolute() or '..' in parts
        or '\\' in relative or '\x00' in relative or relative != PurePosixPath(relative).as_posix()
        or not NAME.fullmatch(parts[0])):
        raise ValueError('Unsafe skill path in installer manifest')
    path = root
    for index, part in enumerate(parts):
        path = path / part
        if path.is_symlink():
            raise ValueError(f'Symlink in skill installation path: {path}')
        if index < len(parts) - 1 and path.exists() and not path.is_dir():
            raise ValueError(f'Skill parent is not a directory: {path}')
    return path


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_file() and path.read_bytes() == data:
        return
    temporary = path.with_name('.deceive-' + uuid.uuid4().hex)
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def install(agent: str = 'all', *, home: Path | None = None, force: bool = False) -> dict:
    if agent not in {'all', 'claude', 'chatgpt'}:
        raise ValueError('Choose --agent all, claude, or chatgpt')
    home = (home or Path.home()).resolve()
    if home.exists() and not home.is_dir():
        raise ValueError('User home is not a directory')
    desired = payloads()
    selected = ('claude', 'chatgpt') if agent == 'all' else (agent,)
    plans = []
    for chosen in selected:
        root = home / ('.claude' if chosen == 'claude' else '.agents') / 'skills'
        for path in (root.parent, root, root / MANIFEST):
            if path.is_symlink():
                raise ValueError(f'Symlink in skill installation path: {path}')
        if any(path.exists() and not path.is_dir() for path in (root.parent, root)):
            raise ValueError(f'Skill installation root is not a directory: {root}')
        manifest = root / MANIFEST
        old = {}
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text())
            except (ValueError, OSError) as exc:
                raise ValueError(f'Invalid installer manifest: {manifest}') from exc
            if not isinstance(data, dict) or data.get('schema_version') != 1 or not isinstance(data.get('files'), dict):
                raise ValueError(f'Invalid installer manifest: {manifest}')
            old = data['files']
            for relative, checksum in old.items():
                safe(root, relative)
                if not isinstance(checksum, str) or not re.fullmatch('[0-9a-f]{64}', checksum):
                    raise ValueError(f'Invalid installer manifest: {manifest}')
        changes = set()
        for relative in desired.keys() | old.keys():
            path = safe(root, relative)
            if path.exists() and not path.is_file():
                raise ValueError(f'Skill file destination is not a regular file: {path}')
            if not path.exists():
                if relative in desired:
                    changes.add(relative)
                continue
            current = path.read_bytes()
            if relative in desired and current == desired[relative]:
                continue
            if not force and (relative not in old or digest(current) != old[relative]):
                raise ValueError(f'Locally edited or unmanaged skill file: {path}; preserve edits or use --force')
            changes.add(relative)
        plans.append((chosen, root, old, changes))

    results = []
    for chosen, root, old, changes in plans:
        root.mkdir(parents=True, exist_ok=True)
        for relative, body in desired.items():
            path = safe(root, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            safe(root, relative)
            atomic_write(path, body)
        obsolete = old.keys() - desired.keys()
        parents = set()
        for relative in obsolete:
            path = safe(root, relative)
            path.unlink(missing_ok=True)
            parents.update(p for p in path.parents if p != root and root in p.parents)
        for directory in sorted(parents, key=lambda p: len(p.parts), reverse=True):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        state = {'schema_version': 1, 'version': version('deceive'),
                 'files': {name: digest(body) for name, body in sorted(desired.items())}}
        atomic_write(root / MANIFEST, (json.dumps(state, indent=2) + '\n').encode())
        previous = {PurePosixPath(k).parts[0] for k in old}
        current = {PurePosixPath(k).parts[0] for k in desired}
        changed = {PurePosixPath(k).parts[0] for k in changes}
        results.append({'agent': chosen, 'directory': str(root), 'added': sorted(current - previous),
                        'updated': sorted(current & previous & changed), 'removed': sorted(previous - current),
                        'unchanged': sorted(current & previous - changed)})
    return {'agents': results, 'skills': sorted({PurePosixPath(k).parts[0] for k in desired})}
