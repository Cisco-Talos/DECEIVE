"""Exercise installed help and skill synchronization without touching a real home."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
from importlib.resources import files
import io
import json
from pathlib import Path
import re
import tempfile
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

from deceive.cli import main


def invoke(arguments: list[str]) -> dict:
    with redirect_stdout(io.StringIO()) as output:
        assert main([*arguments, '--json']) == 0
    return json.loads(output.getvalue())


def check() -> dict:
    assert files('deceive').joinpath('_skill_assets/skills/deceive/SKILL.md').is_file()
    with tempfile.TemporaryDirectory(prefix='deceive-skills-check-') as directory:
        home = Path(directory) / 'user'
        with patch.object(Path, 'home', return_value=home):
            assert invoke(['help', 'profile', 'evaluate'])['data']['topic'] == ['profile', 'evaluate']
            assert not home.exists()
            result = invoke(['install-skills'])
            assert result['data']['skills'] == ['deceive', 'deceive-assess', 'deceive-author']
            root = home / '.agents/skills'
            manifest_path = root / '.deceive-skills.json'
            manifest = json.loads(manifest_path.read_text())
            old = root / 'deceive/SKILL.md'
            old.write_text('Previous installed version\n')
            manifest['files']['deceive/SKILL.md'] = hashlib.sha256(old.read_bytes()).hexdigest()
            retired = root / 'deceive-retired/SKILL.md'
            retired.parent.mkdir()
            retired.write_text('Retired skill\n')
            manifest['files']['deceive-retired/SKILL.md'] = hashlib.sha256(retired.read_bytes()).hexdigest()
            # Represent an older distribution that did not include the author skill.
            import shutil
            shutil.rmtree(root / 'deceive-author')
            manifest['files'] = {k: v for k, v in manifest['files'].items()
                                 if not k.startswith('deceive-author/')}
            manifest_path.write_text(json.dumps(manifest))
            unrelated = root / 'another-skill/SKILL.md'
            unrelated.parent.mkdir()
            unrelated.write_text('Unrelated')
            update = invoke(['install-skills', '--agent', 'chatgpt'])['data']['agents'][0]
            assert update['added'] == ['deceive-author']
            assert update['updated'] == ['deceive'] and update['removed'] == ['deceive-retired']
            assert not retired.parent.exists() and unrelated.read_text() == 'Unrelated'
            assert old.read_text().startswith('---')
            before = {str(p): p.read_bytes() for p in home.rglob('*') if p.is_file()}
            invoke(['install-skills'])
            assert before == {str(p): p.read_bytes() for p in home.rglob('*') if p.is_file()}
            for agent_root in (root, home / '.claude/skills'):
                for path in agent_root.rglob('*.md'):
                    for target in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)', path.read_text()):
                        address = urlsplit(target)
                        if not address.scheme and address.path:
                            assert (path.parent / unquote(address.path)).is_file(), (path, target)
    return {'passed': True, 'agents': ['claude', 'chatgpt'], 'skills': 3,
            'updated_added_removed': True, 'references_resolve': True, 'isolated_home': True}


if __name__ == '__main__':
    print(json.dumps(check()))
