"""Offline installed-device journeys or explicitly configured online smoke.

Online smoke records model use; it does not replace independent research-v4 review.
"""
from __future__ import annotations

import argparse
import base64
import asyncio
from importlib.resources import files
import io
import json
from pathlib import Path
import tempfile

import asyncssh
import yaml

from deceive.catalog import profiles
from deceive.config import load_deployment, load_profile
from deceive.models import Deployment, Listener
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry
from deceive.device.journeys import run_openssh


async def exercise(selected: list[str], *, config_path: Path | None = None,
                   live_model: bool = False, provider: str | None = None,
                   journeys_path: Path | None = None) -> dict:
    if live_model and (config_path is None or not provider):
        raise ValueError('Online checks require --config and an explicit --provider name')
    source = load_deployment(config_path) if config_path else None
    if live_model and provider not in source.providers:
        raise ValueError('Selected provider is not present in local configuration')
    catalog = profiles()
    if not selected and source:
        selections = [choice for listener in source.listeners if listener.enabled
                      for choice in ([listener.profile] if listener.profile else listener.profiles)]
        selections += source.deceptions
        selected = [choice if isinstance(choice,str) else choice.profile for choice in selections]
    selected = selected or [p['id'] for p in catalog
                            if 'ssh.device' in (load_profile(p['reference']).requirements.capabilities
                               if load_profile(p['reference']).requirements else [])]
    journey_text = journeys_path.read_text() if journeys_path else files('deceive').joinpath('journeys/devices.yaml').read_text()
    journeys = yaml.safe_load(journey_text)['journeys']
    outcomes = []
    for name in selected:
        profile = load_profile(name)
        matching = [j for j in journeys if j['profile'] == profile.id]
        if not matching:
            raise ValueError(f'No packaged journey for {profile.id}; use a custom assessment spec for custom targets')
        with tempfile.TemporaryDirectory(prefix='deceive-device-check-') as directory:
            listener = Listener(name='device',protocol='ssh',profile=name,host='127.0.0.1',port=0,
                                accounts={'guest':''},provider=provider if live_model else None)
            config = Deployment(data_dir=Path(directory),listeners=[listener],
                                providers=source.providers if live_model else {},
                                limits=source.limits if source else {})
            telemetry = io.StringIO()
            runtime = Runtime(config, profiles={'device':profile},telemetry=Telemetry('device-check',stream=telemetry))
            try:
                await runtime.start()
                port = runtime.servers['device'].endpoints[0]['port']
                results = [await asyncio.to_thread(run_openssh, port, journey) for journey in matching]
                model_probe = None
                if live_model:
                    async with asyncssh.connect('127.0.0.1',port=port,username='guest',known_hosts=None,encoding=None) as client:
                        result = await client.run('show clock' if profile.device.platform=='ios' else 'uptime',check=False)
                        model_probe = {'exit_status':result.exit_status,'stdout_base64':base64.b64encode(result.stdout).decode()}
            finally:
                await runtime.close()
            records = [json.loads(line) for line in telemetry.getvalue().splitlines()]
            model_calls = [r for r in records if r['message']=='Model call']
            if live_model and not model_calls:
                raise ValueError('Online smoke did not exercise the selected model')
            outcomes.append({'profile':profile.id,'journeys':results,'model_calls':len(model_calls),
                'model_probe':model_probe,'provider':({'kind':source.providers[provider].kind,
                'model':source.providers[provider].model} if live_model else None)})
    return {'passed':True,'live_model':live_model,'realism':'unassessed', 'devices':outcomes}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',action='append',default=[])
    parser.add_argument('--config',type=Path)
    parser.add_argument('--provider')
    parser.add_argument('--journeys',type=Path)
    parser.add_argument('--live-model',action='store_true')
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    result=asyncio.run(exercise(args.profile,config_path=args.config,live_model=args.live_model,provider=args.provider,journeys_path=args.journeys))
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2))
    print(json.dumps({'passed':result['passed'],'live_model':result['live_model'],
                      'devices':len(result['devices']),'realism':result['realism']}))


if __name__=='__main__':
    main()
