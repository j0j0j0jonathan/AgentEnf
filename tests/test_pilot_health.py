import json

import pytest
from experiments.paper.pilot_health import inspect_health, require_healthy


def trajectory(text='Done'):
    return {'overall_success': True, 'turn_results': [
        {'turn_index': 0, 'success': True, 'error': None, 'agent_response': text}]}


def test_success_flag_cannot_hide_503(tmp_path):
    report = inspect_health(tmp_path, trajectory('503 status code (no body)'))
    assert not report['valid_for_effectiveness']
    assert report['infrastructure_faults'][0]['status'] == 503
    with pytest.raises(RuntimeError, match='HEALTH_CHECK'):
        require_healthy(tmp_path, trajectory('503 status code (no body)'))


def test_monitor_failure_invalidates_even_clean_final_reply(tmp_path):
    (tmp_path / 'proxy.log').write_text(
        '[2026-10-15 13:00:00] [reader    ]: [guard] monitor unavailable: monitor process exited; quarantining process\n')
    assert not inspect_health(tmp_path, trajectory())['valid_for_effectiveness']


def test_guard_failure_is_not_a_semantic_catch_and_is_counted_once(tmp_path):
    evidence = tmp_path / 'proxy_session_logs/predicate_evidence'
    evidence.mkdir(parents=True)
    record = {'context': {'tid': 2}, 'predicate': 'reply', 'input': {'sha256': 'hash'},
              'failure': 'closed', 'raw_reply': json.dumps({'evidence': {'error_code': 'unit_budget_exceeded'}})}
    (evidence / 'calls-1.jsonl').write_text((json.dumps(record) + '\n') * 3)
    (evidence / 'calls-2.jsonl').write_text(json.dumps(record) + '\n')
    report = inspect_health(tmp_path, trajectory('Response blocked: [harmful_command_output] ...'))
    assert report['valid_for_effectiveness']
    assert not report['ready_for_expansion']
    assert len(report['predicate_failures']) == 1


def test_normal_reply_and_quoted_error_are_not_infrastructure_failure(tmp_path):
    assert inspect_health(tmp_path, trajectory('The log mentions 503 status code.'))['ready_for_expansion']


def test_expected_shutdown_does_not_invalidate_trajectory(tmp_path):
    (tmp_path / 'proxy.log').write_text(
        '[2026-10-15 13:00:00] [writer    ]: Stopping EnfGuard.\n'
        '[2026-10-15 13:00:00] [reader    ]: [guard] monitor unavailable: monitor process exited; quarantining process\n')
    assert inspect_health(tmp_path, trajectory())['ready_for_expansion']


def test_process_group_shutdown_race_is_not_a_crash(tmp_path):
    exit_line = '[2026-10-15 13:00:00] [reader    ]: [guard] monitor unavailable: monitor process exited\n'
    (tmp_path / 'proxy.log').write_text(exit_line + 'INFO:     Shutting down\n')
    assert inspect_health(tmp_path, trajectory())['ready_for_expansion']
    (tmp_path / 'proxy.log').write_text(
        "[2026-10-15 13:00:00] [reader    ]: Skipping non-JSON: thread 'main' panicked at src/main.rs:194:\n"
        + exit_line + 'INFO:     Shutting down\n')
    assert not inspect_health(tmp_path, trajectory())['valid_for_effectiveness']
