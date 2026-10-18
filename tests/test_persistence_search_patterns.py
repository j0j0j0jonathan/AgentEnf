"""Captured skill inspections are not writes to paths named in grep patterns."""
import json
from pathlib import Path
import pytest
from instrlib.tool_mapper import classify_persistence_command, map_tool_call

CASES = json.loads((Path(__file__).parent/'fixtures/skill_review_persistence.json').read_text())

@pytest.mark.parametrize('row', CASES, ids=lambda row: str(row['tid']))
def test_recorded_skill_inspection_does_not_emit_ssh_persistence(row):
    assert classify_persistence_command(row['input']['command']) is None
    events = map_tool_call(1, 'c', 'exec', row['input'])
    assert not any(e.name == 'Classify' and e.args[2] == 'persistence_kind' for e in events)

@pytest.mark.parametrize('pattern', ["'authorized_keys|/etc/sudoers'", '"authorized_keys|/etc/sudoers"'])
def test_unrelated_redirect_does_not_turn_search_pattern_into_write_target(pattern):
    assert classify_persistence_command(f'echo review > /tmp/review.log; grep -RnE {pattern} /tmp/repo') is None

@pytest.mark.parametrize('command,expected', [
    ("grep 'authorized_keys' /tmp/repo; echo key >> ~/.ssh/authorized_keys", 'ssh_key'),
    ("echo key >> ~/.ssh/authorized_keys; grep 'authorized_keys' /tmp/repo", 'ssh_key'),
    ("grep 'nothing' /tmp/repo > ~/.ssh/authorized_keys", 'ssh_key'),
    ("grep 'nothing' /tmp/repo | tee /etc/sudoers", 'sudoers'),
    ('grep "$(echo key >> ~/.ssh/authorized_keys)" /tmp/repo', 'ssh_key'),
    ('grep "`echo key >> ~/.ssh/authorized_keys`" /tmp/repo', 'ssh_key'),
    ("cp /tmp/key ~/.ssh/authorized_keys", 'ssh_key'),
    ("python3 -c \"open('/root/.ssh/authorized_keys','a').write('key')\"", 'ssh_key'),
])
def test_actual_persistence_effect_remains_visible(command, expected):
    assert classify_persistence_command(command) == expected

@pytest.mark.parametrize('command', [
    "grep '$(echo key >> ~/.ssh/authorized_keys)' /tmp/repo",
    "grep '`echo key >> ~/.ssh/authorized_keys`' /tmp/repo",
    r'grep "\$(echo key >> ~/.ssh/authorized_keys)" /tmp/repo',
    r'grep "\`echo key >> ~/.ssh/authorized_keys\`" /tmp/repo',
    'grep "$(printf \'echo key >> ~/.ssh/authorized_keys\')" /tmp/repo',
])
def test_inert_substitution_text_is_not_write_intent(command):
    assert classify_persistence_command(command) is None
