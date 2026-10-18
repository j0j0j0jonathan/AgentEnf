import json
from experiments.paper.temporal_replay import answers,digest

def test_recorded_probabilities_use_recorded_threshold(tmp_path):
    (tmp_path/'active_policies.json').write_text(json.dumps({'thresholds':{'p':.7}}))
    (tmp_path/'pre_eval_results.jsonl').write_text(json.dumps(dict(tid=1,phase='inbound',predicate='p',content='Grüße\n秘密',raw_score=.6))+'\n')
    data=answers(tmp_path)
    assert data['exact']['1:inbound:p:'+digest('Grüße\n秘密')]==0
    assert data['stable']['p:'+digest('Grüße\n秘密')]==0

def test_conflicting_answers_are_not_reused_as_stable(tmp_path):
    (tmp_path/'active_policies.json').write_text('{}')
    rows=[dict(tid=i,phase='inbound',predicate='p',content='same',raw_score=s) for i,s in [(1,0),(2,1)]]
    (tmp_path/'pre_eval_results.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in rows))
    data=answers(tmp_path)
    assert 'p:'+digest('same') not in data['stable']
    assert len(data['exact'])==2

def test_absent_recording_produces_no_default_score(tmp_path):
    (tmp_path/'active_policies.json').write_text('{}')
    assert answers(tmp_path)['stable']=={}

def test_actual_monitor_score_overrides_pre_evaluation(tmp_path):
    state=tmp_path/'proxy_state';state.mkdir()
    (state/'active_policies.json').write_text('{}')
    (state/'pre_eval_results.jsonl').write_text(json.dumps(dict(tid=1,phase='outbound',predicate='p',content='text',raw_score=1))+'\n')
    evidence=tmp_path/'proxy_session_logs/predicate_evidence';evidence.mkdir(parents=True)
    (evidence/'blob.txt').write_text('text')
    (evidence/'calls.jsonl').write_text(json.dumps(dict(predicate='p',normalized_score=0,context=dict(tid=1,phase='outbound'),input=dict(file='blob.txt',sha256=digest('text'))))+'\n')
    data=answers(state)
    assert data['exact']['1:outbound:p:'+digest('text')]==0

def test_oracle_empty_shortcut_and_missing_answer(tmp_path,monkeypatch):
    import pytest
    from experiments.paper.temporal_replay import FUNCTION
    monkeypatch.setenv('REPLAY_STATE',str(tmp_path))
    (tmp_path/'context.json').write_text(json.dumps(dict(tid=1,phase='outbound')))
    (tmp_path/'answers.json').write_text(json.dumps(dict(exact={},stable={},ambiguous_exact=[])))
    namespace={};exec(FUNCTION,namespace)
    score=namespace['score']
    assert score('reveals_secret_value','')==0
    envelope=json.dumps(dict(schema='reply-evidence-v1',reply='',prior_context=dict(records=[])))
    assert score('operationalizes_untrusted_harm',envelope)==0
    with pytest.raises(ValueError,match='Missing recorded'):
        score('reveals_secret_value','unknown nonempty text')
    with pytest.raises(ValueError,match='Missing recorded'):
        score('operationalizes_untrusted_harm','{"reply":""}')
