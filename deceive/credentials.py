"""Explicit local secret sources. No shell evaluation or global environment mutation."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shlex

from deceive.models import ProviderConfig


DEFAULT_ENV = {
    'openai': ('OPENAI_API_KEY',), 'azure': ('AZURE_OPENAI_API_KEY',),
    'gemini': ('GOOGLE_API_KEY', 'GEMINI_API_KEY'), 'ollama': (),
    'bedrock': ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                'AWS_REGION', 'AWS_DEFAULT_REGION', 'AWS_PROFILE', 'AWS_DEFAULT_PROFILE'),
}


def read_env_file(path: Path | None, *, required: bool = False) -> dict[str, str]:
    if path is None:
        return {}
    if not path.is_file():
        if required:
            raise ValueError('Configured environment file is missing')
        return {}
    if path.stat().st_size > 1048576:
        raise ValueError('Environment file exceeds 1 MiB')
    values = {}
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        name, separator, value = line.partition('=')
        name, value = name.strip(), value.strip()
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) or name in values:
            raise ValueError(f'Invalid or duplicate environment assignment on line {number}')
        try:
            parsed = shlex.split(value, comments=True, posix=True)
        except ValueError:
            raise ValueError(f'Invalid environment quoting on line {number}') from None
        if len(parsed) > 1:
            raise ValueError(f'Quote whitespace in environment values on line {number}')
        values[name] = parsed[0] if parsed else ''
    return values


def literal_name(alias: str) -> str:
    return 'DECEIVE_PROVIDER_' + hashlib.sha256(alias.encode()).hexdigest()[:16].upper() + '_KEY'


def provider_environment(provider: ProviderConfig, alias: str) -> dict[str, str]:
    if provider.api_key_file:
        return {}
    if provider.api_key is not None:
        return {literal_name(alias): provider.api_key.get_secret_value()}
    source = read_env_file(provider.env_file)
    source.update(os.environ)
    names = (provider.api_key_env,) if provider.api_key_env else DEFAULT_ENV[provider.kind]
    if provider.kind == 'bedrock':
        names = ()
        if provider.region is None:
            names += ('AWS_REGION', 'AWS_DEFAULT_REGION')
        if provider.aws_profile is None:
            if source.get('AWS_PROFILE') or source.get('AWS_DEFAULT_PROFILE'):
                names += ('AWS_PROFILE', 'AWS_DEFAULT_PROFILE')
            else:
                names += ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')
    return {name: source[name] for name in names if source.get(name)}


def selected_environment(providers: dict[str, ProviderConfig], selected: set[str]) -> dict[str, str]:
    result = {}
    for alias in sorted(selected):
        for name, value in provider_environment(providers[alias], alias).items():
            if name in result and result[name] != value:
                raise ValueError(f'Conflicting selected secret sources for environment variable {name}')
            result[name] = value
    return result
