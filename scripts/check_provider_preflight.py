"""Offline CLI/SDK integration against a local mock model API, including startup gating."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile


async def exercise(root: Path) -> dict:
    calls = []
    state = {'status': 200}
    key = 'private-preflight-fixture'

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
            fields = dict(line.split(b':', 1) for line in header.split(b'\r\n')[1:] if b':' in line)
            fields = {name.lower(): value.strip() for name, value in fields.items()}
            body = await reader.readexactly(int(fields[b'content-length']))
            assert fields[b'authorization'] == ('Bearer ' + key).encode()
            request = json.loads(body)
            assert request['model'] == 'configured-model'
            assert request['max_completion_tokens'] == 2048
            assert request['temperature'] == .2
            calls.append(request)
            if state['status'] == 200:
                response = {'id':'fixture', 'object':'chat.completion', 'created':0,
                    'model':'configured-model', 'choices':[{'index':0,
                    'message':{'role':'assistant','content':'ready'}, 'finish_reason':'stop'}],
                    'usage':{'prompt_tokens':3,'completion_tokens':1,'total_tokens':4}}
            else:
                response = {'error':{'message': key + ' must never appear in output',
                                    'type':'invalid_api_key','code':'invalid_api_key'}}
            encoded = json.dumps(response).encode()
            status = b'200 OK' if state['status'] == 200 else b'401 Unauthorized'
            writer.write(b'HTTP/1.1 ' + status + b'\r\nContent-Type: application/json\r\n'
                         + b'Connection: close\r\nContent-Length: ' + str(len(encoded)).encode()
                         + b'\r\n\r\n' + encoded)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    provider = {'kind':'openai','model':'configured-model','endpoint':f'http://127.0.0.1:{port}/v1',
                'api_key_env':'DECEIVE_PREFLIGHT_FIXTURE_KEY'}
    (root / 'providers.local.yaml').write_text(json.dumps({'env_file': '.env',
        'providers': {'one': provider, 'duplicate': provider,
                      'unused': dict(provider, api_key_env='DECEIVE_ABSENT_FIXTURE_KEY')}}))
    env_file = root / '.env'
    env_file.write_text('DECEIVE_PREFLIGHT_FIXTURE_KEY=' + key + '\nUNRELATED=unused-secret\n')
    config = {'data_dir':str(root / 'data'), 'provider_config':'providers.local.yaml',
        'listeners':[{'name':alias,'protocol':'ssh','profile':'linux-device','provider':alias,
                      'host':'127.0.0.1','port':0} for alias in ('one','duplicate')],
        'limits':{'request_seconds':3,'llm_seconds':2}}
    path = root / 'deployment.json'
    path.write_text(json.dumps(config))
    environment = dict(os.environ)
    environment.pop('DECEIVE_PREFLIGHT_FIXTURE_KEY', None)
    environment.pop('DECEIVE_ABSENT_FIXTURE_KEY', None)

    async def command(*arguments: str, env: dict | None = None) -> tuple[int, str, str]:
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'deceive',
            *arguments, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=environment if env is None else env)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.communicate()
            raise
        output, error = stdout.decode(), stderr.decode()
        assert key not in output + error
        return process.returncode, output, error

    try:
        status, output, _ = await command('config','validate','--config',str(path),'--json')
        assert status == 0 and json.loads(output)['data']['validation']['verification'] == 'live-verified'
        assert len(calls) == 1 and not (root / 'data').exists()
        no_credentials = dict(environment)
        saved_env = env_file.read_text()
        env_file.unlink()
        status, output, _ = await command('config','validate','--config',str(path),'--offline',
                                          '--json',env=no_credentials)
        assert status == 0 and json.loads(output)['data']['validation']['verification'] == 'offline-valid'
        assert len(calls) == 1
        env_file.write_text(saved_env)
        state['status'] = 401
        status, output, _ = await command('config','validate','--config',str(path),'--json')
        assert status == 2 and json.loads(output)['error']['code'] == 'provider_preflight_failed'
        assert len(calls) == 2
        status, output, _ = await command('serve','--config',str(path),'--preflight')
        assert status == 2
        records = [json.loads(line) for line in output.splitlines()]
        assert not any(row['message'] == 'Listener started' for row in records)
        assert any(row['message'] == 'Provider preflight' and not row['passed'] for row in records)
        assert len(calls) == 3 and not (root / 'data/status.json').exists()
        state['status'] = 200
        process = await asyncio.create_subprocess_exec(sys.executable,'-m','deceive','serve',
            '--config',str(path),'--preflight',stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,env=environment)
        try:
            for _ in range(100):
                status_path = root / 'data/status.json'
                if status_path.exists() and json.loads(status_path.read_text())['ready']:
                    break
                if process.returncode is not None:
                    raise AssertionError('Checked server exited before readiness')
                await asyncio.sleep(.05)
            else:
                raise AssertionError('Checked server did not become ready')
            assert len(calls) == 4
        finally:
            if process.returncode is None:
                process.terminate()
            stdout, stderr = await asyncio.wait_for(process.communicate(), 5)
            assert key.encode() not in stdout + stderr
        assert process.returncode == 0
        return {'passed':True,'live_llm_calls':0,'mock_api_requests':len(calls),
                'deduplicated':True,'offline_without_credentials':True,
                'authentication_failure_sanitized':True,'failure_before_listeners':True,
                'successful_startup_gate':True, 'shared_catalog_and_dotenv':True}
    finally:
        server.close()
        await server.wait_closed()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix='deceive-preflight-check-') as directory:
        print(json.dumps(asyncio.run(exercise(Path(directory)))))


if __name__ == '__main__':
    main()
