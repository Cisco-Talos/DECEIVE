"""Installed-package contract acceptance; deterministic and entirely loopback."""
from __future__ import annotations

import asyncio
import base64
from importlib.resources import files
import json
from pathlib import Path
import tempfile

from deceive.config import load_profile, read_yaml
from deceive.evaluate import evaluate


async def verify() -> None:
    with tempfile.TemporaryDirectory(prefix='deceive-contracts-') as directory:
        root = Path(directory)
        org = root / 'organization.yaml'
        org.write_text('id: installed\nvalues: {organization_name: Installed Research, tenant_id: installed}\n')
        for suffix in ('linux', 'cmd', 'ps51', 'ps7'):
            name = 'workbench-http-' + suffix
            bound = load_profile(name, organization=org, instance_id='installed-' + suffix)
            assert bound.identity.banner == 'Welcome to Installed Research'
            status = next(contract for contract in bound.contracts if contract.id == 'status')
            assert status.http.path == '/api/installed/status'
            head = next(contract for contract in bound.contracts if contract.id == 'status-head')
            assert head.http.path == status.http.path and head.http.method == 'HEAD'
            suite = files('deceive').joinpath('acceptance', name + '.yaml')
            suite_path = Path(str(suite))
            if suffix in ('ps51', 'ps7'):
                raw = read_yaml(suite_path)
                output = b'first\r\nsecond\r\n'
                raw['cases'].append({'id':'installed-mixed-encoding', 'steps': [
                    {'method':'POST','path':'/api/demo/command','body':json.dumps({'command':text}),
                     'expect':{'status':200} if index < 2 else {'json_value':{
                         'stdout':output.decode(), 'stderr':'', 'exit_status':0,
                         'stdout_base64':base64.b64encode(output).decode(),'stderr_base64':''}}}
                    for index,text in enumerate((r'Write-Output first > C:\Temp\mixed',
                        r'Add-Content C:\Temp\mixed second',r'Get-Content C:\Temp\mixed'))]})
                suite_path = root/(name+'-suite.json')
                suite_path.write_text(json.dumps(raw))
            result = await evaluate(name, suite_path, root / name)
            assert result['passed_cases'] == result['total_cases'] and result['passed'], result
        print(json.dumps({'contract_profiles': 4, 'organization_binding': True,
                          'powershell_encoding_followups': True, 'live_models': False}))


if __name__ == '__main__':
    asyncio.run(verify())
