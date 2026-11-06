import json
from pathlib import Path

from deceive.composition import resolve
from deceive.config import load_deployment, load_profile
from deceive.managed import snapshot_profile
from deceive.assessment.workspace import stage_profile


def test_snapshot_embeds_bound_values_assets_and_complete_base(tmp_path):
    base = tmp_path / 'base.yaml'
    base.write_text('schema_version: 2\nid: base\nprotocol: http\nparameters:\n  tenant: {type: string, default: demo}\nidentity: {banner: "${tenant}"}\n')
    asset = tmp_path / 'reply.txt'
    asset.write_text('bound ${tenant}')
    child = tmp_path / 'child.yaml'
    child.write_text('schema_version: 2\nid: child\nrequirements: {protocol: http, base_profile: base.yaml, base_version: "1"}\ncontracts:\n- id: greeting\n  http: {path: "/${tenant}"}\n  reply: {body_template_file: reply.txt}\n')
    member = load_profile(str(child), parameters={'tenant': 'actual'}, instance_id='custom')
    stage = tmp_path / 'snapshot'
    stage.mkdir()
    reference = snapshot_profile(str(child), stage, profile=member)
    asset.unlink()
    base.unlink()
    child.unlink()
    raw = json.loads((stage / Path(reference).name).read_text())
    # Convert container path prefixes to the isolated snapshot directory for replay.
    for path in stage.iterdir():
        path.write_text(path.read_text().replace('/config/', str(stage) + '/'))
    restored = load_profile(str(stage / Path(reference).name))
    assert restored.instance_id == 'custom'
    assert restored.contracts[0].reply.body == 'bound actual'
    plan = resolve(__import__('deceive.models', fromlist=['Deployment']).Deployment(
        listeners=[{'protocol': 'http', 'profile': str(stage / Path(reference).name)}]))
    assert next(iter(plan.profiles.values())).identity.banner == 'actual'
