"""Resolve a shared provider catalog without interpolating profile/application content."""
from __future__ import annotations

import os
from pathlib import Path
import re

from deceive.credentials import read_env_file

REFERENCE = re.compile(r'\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}')


def resolve_provider_settings(raw: dict, base: Path) -> dict:
    from deceive.config import read_yaml, relative_path
    raw = dict(raw)
    catalog = {}
    catalog_base = base
    reference = raw.pop('provider_config', None)
    if reference:
        if not isinstance(reference, str):
            raise ValueError('provider_config must name one YAML file')
        path = relative_path(base, reference)
        catalog = read_yaml(path)
        if set(catalog) - {'schema_version', 'providers', 'default_provider', 'env_file'}:
            raise ValueError('Unknown shared provider catalog field')
        if catalog.get('schema_version', 1) != 1:
            raise ValueError('Unsupported provider catalog version')
        catalog_base = path.parent
    if 'default_provider' not in raw and 'default_provider' in catalog:
        raw['default_provider'] = catalog['default_provider']
    local_env = raw.pop('env_file', None)
    local_providers = raw.get('providers') or {}
    shared = catalog.get('providers') or {}
    if not isinstance(local_providers, dict) or not isinstance(shared, dict):
        raise ValueError('Provider catalogs must contain a mapping of named providers')
    resolved = {}
    for alias, spec in (shared | local_providers).items():
        if not isinstance(spec, dict):
            raise ValueError('Each named provider must be a mapping')
        owner = base if alias in local_providers else catalog_base
        env_ref = spec.get('env_file', local_env if local_env is not None else catalog.get('env_file'))
        env_owner = owner if 'env_file' in spec else base if local_env is not None else catalog_base
        env_path = relative_path(env_owner, env_ref) if env_ref else None
        environment = read_env_file(env_path)
        environment.update(os.environ)
        value = dict(spec)
        if env_path:
            value['env_file'] = str(env_path)
        else:
            value.pop('env_file', None)
        key = value.get('api_key')
        match = REFERENCE.fullmatch(key) if isinstance(key, str) else None
        if match:
            if value.get('api_key_env') or value.get('api_key_file'):
                raise ValueError('Choose one provider credential reference')
            value.pop('api_key')
            value['api_key_env'] = match[1]
        for field, content in list(value.items()):
            if not isinstance(content, str) or field in {'api_key', 'api_key_env', 'env_file'}:
                continue
            def substitute(match: re.Match) -> str:
                if match[1] not in environment:
                    raise ValueError(f'Missing configuration environment variable {match[1]}')
                return environment[match[1]]
            value[field] = REFERENCE.sub(substitute, content)
        if value.get('api_key_file'):
            value['api_key_file'] = str(relative_path(owner, value['api_key_file']))
        resolved[alias] = value
    raw['providers'] = resolved
    return raw
