import json
from pathlib import Path
import re

import pytest

from deceive.cli import main, parser


def bundle(root, names=('deceive', 'deceive-author')):
    for name in names:
        p = root / 'skills' / name
        p.mkdir(parents=True, exist_ok=True)
        (p / 'SKILL.md').write_text(f'---\nname: {name}\ndescription: Test skill\n---\nRead [guide](../../docs/profiles.md).\n')
    (root / 'docs').mkdir(exist_ok=True)
    (root / 'docs/profiles.md').write_text('Guide v1\n')
    return root


def test_cli_default_installs_both_agents_and_portable_references(tmp_path, monkeypatch, capsys):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    monkeypatch.setattr(Path, 'home', lambda: home)
    assert main(['install-skills', '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['operation'] == 'install-skills' and result['ok']
    for directory in (home / '.claude/skills', home / '.agents/skills'):
        text = (directory / 'deceive/SKILL.md').read_text()
        assert '(references/docs/profiles.md)' in text
        assert (directory / 'deceive/references/docs/profiles.md').read_text() == 'Guide v1\n'
    assert not (home / '.codex').exists()


def test_updater_changes_adds_removes_and_preserves_unmanaged_files(tmp_path, monkeypatch):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets', ('deceive', 'deceive-old'))
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    install_skills.install('chatgpt', home=home)
    root = home / '.agents/skills'
    (root / 'unrelated').mkdir()
    (root / 'unrelated/SKILL.md').write_text('Do not touch')
    (root / 'deceive/notes.txt').write_text('Keep my note')
    import shutil
    shutil.rmtree(assets / 'skills/deceive-old')
    bundle(assets, ('deceive', 'deceive-new'))
    (assets / 'docs/profiles.md').write_text('Guide v2\n')
    result = install_skills.install('chatgpt', home=home)
    assert (root / 'deceive/references/docs/profiles.md').read_text() == 'Guide v2\n'
    assert (root / 'deceive-new/SKILL.md').is_file()
    assert not (root / 'deceive-old').exists()
    assert (root / 'unrelated/SKILL.md').read_text() == 'Do not touch'
    assert (root / 'deceive/notes.txt').read_text() == 'Keep my note'
    before = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    install_skills.install('chatgpt', home=home)
    assert before == {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert not (home / '.claude').exists()


def test_conflicts_preflight_all_agents_and_force_is_explicit(tmp_path, monkeypatch):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    install_skills.install('all', home=home)
    edited = home / '.agents/skills/deceive/SKILL.md'
    edited.write_text('My local edit')
    previous = (home / '.claude/skills/deceive/references/docs/profiles.md').read_bytes()
    (assets / 'docs/profiles.md').write_text('New version')
    with pytest.raises(ValueError, match='--force'):
        install_skills.install('all', home=home)
    assert (home / '.claude/skills/deceive/references/docs/profiles.md').read_bytes() == previous
    assert edited.read_text() == 'My local edit'
    install_skills.install('all', home=home, force=True)
    assert edited.read_text().startswith('---')


def test_symlink_and_corrupt_manifest_never_write_outside_managed_root(tmp_path, monkeypatch):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    root = home / '.agents/skills'
    root.mkdir(parents=True)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (root / 'deceive').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match='[Ss]ymlink'):
        install_skills.install('chatgpt', home=home, force=True)
    assert not list(outside.iterdir())
    (root / 'deceive').unlink()
    (root / '.deceive-skills.json').write_text(json.dumps({'schema_version': 1, 'files': {'../outside/file': 'bad'}}))
    with pytest.raises(ValueError, match='manifest'):
        install_skills.install('chatgpt', home=home)
    assert not list(outside.iterdir())


def all_commands(command=None, path=()):
    command = command or parser()
    yield path
    import argparse
    for action in command._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from all_commands(child, (*path, name))


def test_every_command_accepts_both_help_flags_without_side_effects(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)
    for path in all_commands():
        for flag in ('-h', '--help'):
            with pytest.raises(SystemExit) as stopped:
                main([*path, flag])
            assert stopped.value.code == 0, (path, flag)
            assert 'usage:' in capsys.readouterr().out
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('path', [[], ['profile'], ['profile', 'evaluate'], ['assess', 'probe'], ['install-skills']])
def test_help_command_can_describe_nested_commands_without_required_args(path, capsys):
    assert main(['help', *path]) == 0
    text = capsys.readouterr().out
    assert 'usage:' in text and '--help' in text
    if path: assert path[-1] in text


def test_help_unknown_target_and_bad_agent_are_errors(capsys):
    assert main(['help', 'unknown', '--json']) == 2
    assert not json.loads(capsys.readouterr().out)['ok']
    assert main(['install-skills', '--agent', 'unknown', '--json']) == 2
    assert not json.loads(capsys.readouterr().out)['ok']


def test_obsolete_assets_are_removed_but_extra_notes_survive(tmp_path, monkeypatch):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets', ('deceive', 'deceive-old'))
    (assets / 'docs/retired.md').write_text('Old reference')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    install_skills.install('claude', home=home)
    root = home / '.claude/skills'
    (root / 'deceive-old/personal.txt').write_text('Preserve')
    import shutil
    shutil.rmtree(assets / 'skills/deceive-old')
    (assets / 'docs/retired.md').unlink()
    install_skills.install('claude', home=home)
    assert not (root / 'deceive/references/docs/retired.md').exists()
    assert not (root / 'deceive-old/SKILL.md').exists()
    assert (root / 'deceive-old/personal.txt').read_text() == 'Preserve'


def test_modified_obsolete_files_require_force_and_parents_are_preflighted(tmp_path, monkeypatch):
    from deceive import install_skills

    assets = bundle(tmp_path / 'assets', ('deceive', 'deceive-old'))
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    install_skills.install('chatgpt', home=home)
    root = home / '.agents/skills'
    (root / 'deceive-old/SKILL.md').write_text('Local edit')
    import shutil
    shutil.rmtree(assets / 'skills/deceive-old')
    with pytest.raises(ValueError, match='--force'):
        install_skills.install('chatgpt', home=home)
    install_skills.install('chatgpt', home=home, force=True)
    assert not (root / 'deceive-old').exists()
    shutil.rmtree(root / 'deceive/references')
    (root / 'deceive/references').write_text('File blocks directory')
    with pytest.raises(ValueError, match='parent'):
        install_skills.install('chatgpt', home=home, force=True)


def test_actual_bundled_skill_links_resolve_after_installation(tmp_path):
    from deceive.install_skills import install
    from urllib.parse import urlsplit, unquote

    install('chatgpt', home=tmp_path)
    root = tmp_path / '.agents/skills'
    assert {p.name for p in root.iterdir() if p.is_dir()} == {'deceive', 'deceive-author', 'deceive-assess'}
    for path in root.rglob('*.md'):
        for _, target in re.findall(r'\[([^\]\n]+)\]\(([^)\n]+)\)', path.read_text()):
            address = urlsplit(target)
            if not address.scheme and address.path:
                assert (path.parent / unquote(address.path)).is_file(), (path, target)


def test_packaged_assets_are_in_assessment_snapshot(tmp_path):
    from deceive.assessment.workspace import checkpoint

    root = Path(__file__).resolve().parents[1]
    # Reuse the real checkout without editing it; output lives only in tmp_path.
    snapshot = checkpoint(root, tmp_path)
    assert {'hatch_build.py', 'skills/deceive/SKILL.md', 'docs/operations.md',
            'examples/assessment.yaml'} <= snapshot['files'].keys()
    assert (tmp_path / 'source/hatch_build.py').is_file()


def test_asset_updates_invalidate_image_and_private_material_is_excluded(tmp_path, monkeypatch):
    from deceive import install_skills
    from deceive.assessment.workspace import checkpoint

    root = bundle(tmp_path / 'repo')
    monkeypatch.setattr('deceive.assessment.workspace.git', lambda *args: 'fixture')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: root)
    (root / 'skills/deceive/private.key').write_text('Never install')
    (root / 'skills/deceive/.env').write_text('Never install')
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(); second.mkdir()
    before = checkpoint(root, first)
    assert not any(name.endswith(('.key', '.env')) for name in before['files'])
    (root / 'docs/profiles.md').write_text('Changed asset')
    after = checkpoint(root, second)
    assert before['server_id'] != after['server_id']
    assert not any(name.endswith(('.key', '.env')) for name in install_skills.payloads())


@pytest.mark.parametrize('relative', ['deceive//SKILL.md', 'deceive/./SKILL.md'])
def test_noncanonical_manifest_cannot_delete_a_current_skill(tmp_path, monkeypatch, relative):
    from deceive import install_skills
    import hashlib

    assets = bundle(tmp_path / 'assets')
    monkeypatch.setattr(install_skills, 'bundle_root', lambda: assets)
    home = tmp_path / 'home'
    install_skills.install('chatgpt', home=home)
    root = home / '.agents/skills'
    current = (root / 'deceive/SKILL.md').read_bytes()
    manifest = json.loads((root / '.deceive-skills.json').read_text())
    manifest['files'][relative] = hashlib.sha256(current).hexdigest()
    (root / '.deceive-skills.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='manifest'):
        install_skills.install('chatgpt', home=home)
    assert (root / 'deceive/SKILL.md').read_bytes() == current


def test_invalid_second_agent_root_is_preflighted_before_first_install(tmp_path, monkeypatch):
    from deceive import install_skills

    monkeypatch.setattr(install_skills, 'bundle_root', lambda: bundle(tmp_path / 'assets'))
    home = tmp_path / 'home'
    (home / '.agents').mkdir(parents=True)
    (home / '.agents/skills').write_text('Not a directory')
    with pytest.raises(ValueError, match='directory'):
        install_skills.install('all', home=home)
    assert not (home / '.claude').exists()
