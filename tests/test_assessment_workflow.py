import base64
from pathlib import Path

import pytest

from deceive.assessment.models import CoverageGoal, EvidenceRule, ProbeAction, Spec, Target
from deceive.assessment.quality import rules_match, sequence


def test_windows_capture_normalization_is_explicit_and_does_not_rewrite_content():
    capture = EvidenceRule.model_validate({'field': 'action.parameters.path', 'capture': 'path',
                                          'normalize': 'windows_path'})
    compare = EvidenceRule.model_validate({'field': 'action.parameters.path', 'equals_capture': 'path',
                                          'normalize': 'windows_path'})
    def event(path): return {'action': {'parameters': {'path': path}}}
    values = rules_match(event('"C:\\Temp\\My File.txt"'), [capture], {})
    assert rules_match(event('c:/temp/my file.TXT'), [compare], values) is not None
    assert rules_match(event('c:/temp/another.txt'), [compare], values) is None
    # Legacy captures remain exact and content is never normalized implicitly.
    legacy = EvidenceRule(field='action.parameters.path', capture='path')
    exact = EvidenceRule(field='action.parameters.path', equals_capture='path')
    assert rules_match(event('c:/temp/my file.TXT'), [exact],
                       rules_match(event('"C:\\Temp\\My File.txt"'), [legacy], {})) is None
    assert 'normalize' not in legacy.model_dump(mode='json')


def plan_fixture():
    goal = CoverageGoal.model_validate({'id':'state','role':'attacker',
        'criterion':'followup_effects','kind':'state','description':'Write then read same private key',
        'same_session':True,'every_version':True,'steps':[
            {'select':[{'field':'action.parameters.method','equals':'POST'},
                       {'field':'action.parameters.path','capture':'key'}],
             'expect':[{'field':'facts.status','equals':201}]},
            {'select':[{'field':'action.parameters.method','equals':'GET'},
                       {'field':'action.parameters.path','equals_capture':'key'}],
             'expect':[{'field':'body_text','equals':'PRIVATE ANSWER NEVER PUBLIC'}]}]})
    target = Target(name='fixture', profiles=['demo-http'], coverage=[goal])
    entry = {'endpoints':[{'id':'service-1','protocol':'https','versions':['2','3']}]}
    actions = [ProbeAction(operation='request',session='owner',parameters={
        'method':m,'path':'/unique','version':v}) for v in ['2','3'] for m in ['POST','GET']]
    return target,entry,actions


def test_plan_preflight_catches_order_session_version_and_budget_without_answers():
    from deceive.assessment.workflow import check_plan
    target,entry,actions=plan_fixture()
    good=check_plan(target,entry,'attacker',actions,limit=12,reserve=4)
    assert good['ready'] and good['actions']==4
    assert 'PRIVATE ANSWER' not in str(good) and '201' not in str(good)
    for changed in [actions[:2],list(reversed(actions)),
                    [a.model_copy(update={'session':str(i)}) for i,a in enumerate(actions)]]:
        assert not check_plan(target,entry,'attacker',changed,limit=12,reserve=4)['ready']
    assert not check_plan(target,entry,'attacker',actions,limit=6,reserve=4)['ready']


def test_plan_preflight_does_not_treat_cleanup_as_substantive_or_execute_input():
    from deceive.assessment.workflow import check_plan
    target,entry,actions=plan_fixture()
    actions[0].operation='close'
    assert not check_plan(target,entry,'attacker',actions,limit=12,reserve=4)['ready']
    target.coverage[0].steps[0].select=[EvidenceRule(field='facts.unpredictable',equals=True)]
    result=check_plan(target,entry,'attacker',actions,limit=12,reserve=4)
    assert not result['ready'] and result['uncheckable']


def test_quoted_case_variant_paths_link_but_exact_content_still_fails():
    path=r'''(?:"C:[\\/]Temp[\\/][^"\r\n]+"|'C:[\\/]Temp[\\/][^'\r\n]+'|C:[\\/]Temp[\\/][A-Za-z0-9_.-]+)'''
    goal=CoverageGoal.model_validate({'id':'state','role':'attacker',
        'criterion':'followup_effects','kind':'state','description':'Write/read virtual bytes',
        'steps':[
            {'select':[{'field':'action.parameters.command','pattern':r'^write ('+path+r')$',
                        'capture':'path','normalize':'windows_path'}]},
            {'select':[{'field':'action.parameters.command','pattern':r'^read ('+path+r')$',
                        'equals_capture':'path','normalize':'windows_path'}],
             'expect':[{'field':'body_text','equals':'EXACT\r\n'}]}]})
    def event(i,c,body=''):return {'interaction_id':str(i),'action':{'parameters':{'command':c}},
                                  'body_base64':base64.b64encode(body.encode()).decode()}
    seen=[event(1,'write "C:\\Temp\\My File"'),event(2,"read 'C:/Temp/my file'",'EXACT\r\n')]
    assert sequence(goal,seen)['expectations_passed']
    seen[1]=event(2,"read 'C:/Temp/my file'",'exact\r\n')
    result=sequence(goal,seen)
    assert result['exercised'] and not result['expectations_passed']


def test_gap_labels_distinguish_review_harness_infrastructure_and_defects():
    from deceive.assessment.dashboard import gap_label
    assert len({gap_label({'assessment_issues':[{'category':kind}]})[0] for kind in [
        'incomplete_review','harness_error','infrastructure_interruption','deception_defect']})==4


@pytest.mark.asyncio
async def test_schema2_broker_rejects_unplanned_probes_without_spending_budget(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from deceive.assessment.broker import Broker
    from deceive.assessment.workspace import write_json
    target,entry,_=plan_fixture()
    spec=Spec(schema_version=2,targets=[target])
    current={'directory':'attempt','candidate_id':'current','targets':{'target-01':entry}}
    write_json(tmp_path/'state.json',{'spec':spec.model_dump(mode='json'),'current':current,'started_epoch':0})
    broker=Broker(tmp_path)
    broker.drivers=SimpleNamespace(execute=AsyncMock(return_value={'version':'2'}))
    action=ProbeAction(operation='request',parameters={'method':'GET','path':'/','version':'2'})
    with pytest.raises(ValueError,match='plan'):
        await broker.probe('attacker','target-01',action)
    assert not (tmp_path/'attempt/probe-budget.json').exists()
    assert not broker.drivers.execute.called


def test_plan_closes_do_not_require_http_version_and_typos_are_rejected():
    from deceive.assessment.workflow import check_plan
    target,entry,actions=plan_fixture()
    actions.append(ProbeAction(operation='close',session='owner'))
    assert check_plan(target,entry,'attacker',actions,limit=12,reserve=4)['ready']
    actions.append(ProbeAction(operation='requset',parameters={'version':'2'}))
    assert not check_plan(target,entry,'attacker',actions,limit=12,reserve=4)['ready']


def test_ssh_authentication_can_be_preflighted_as_an_assessment_action():
    from deceive.assessment.workflow import check_plan
    goal = CoverageGoal.model_validate({
        'id': 'ssh-boundary', 'role': 'product', 'criterion': 'required_behavior',
        'kind': 'positive', 'description': 'Exercise a real password-auth exchange',
        'steps': [{'select': [
            {'field': 'action.operation', 'equals': 'authenticate'},
            {'field': 'action.parameters.username', 'equals': 'deploy'},
        ]}],
    })
    target = Target(name='ssh', profiles=['sshhole-2026-123158'], coverage=[goal])
    entry = {'endpoints': [{'id': 'service-1', 'protocol': 'ssh', 'versions': []}]}
    actions = [ProbeAction(operation='authenticate', parameters={
        'username': 'deploy', 'password': 'A' * 257})]
    assert check_plan(target, entry, 'product', actions, limit=10, reserve=2)['ready']


def test_new_specs_default_to_audited_workflow_and_explicit_legacy_is_preserved():
    target=Target(name='demo',profiles=['demo-http'])
    assert Spec(targets=[target]).schema_version==2
    assert Spec(schema_version=1,targets=[target]).schema_version==1
