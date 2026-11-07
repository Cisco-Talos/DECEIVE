"""Bundle canonical skills and their portable reading assets without runtime data."""
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class SkillAssetsHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict) -> None:
        if self.target_name != 'wheel':
            return
        root = Path(self.root)
        paths = [p for p in (root / 'skills').rglob('*') if p.is_file()
                 and p.suffix not in {'.pyc', '.key', '.pem'} and not p.name.endswith('_host_key')
                 and not any(part.startswith('.') or part == '__pycache__'
                             for part in p.relative_to(root).parts)]
        paths += list((root / 'docs').glob('*.md'))
        paths += list((root / 'examples').glob('*.yaml'))
        paths += list((root / 'examples/profiles').glob('*.yaml'))
        paths += [root / 'README.md', root / 'LICENSE']
        for path in paths:
            if path.name.endswith('.local.yaml'):
                continue
            if path.is_symlink():
                raise ValueError('Skill assets must not be symlinks')
            relative = path.relative_to(root).as_posix()
            build_data['force_include'][str(path)] = 'deceive/_skill_assets/' + relative
