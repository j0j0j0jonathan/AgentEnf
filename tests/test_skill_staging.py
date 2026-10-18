"""Skill observations and policy precision, without executing shell or APIs."""
import os
from pathlib import Path
import shlex

import pytest
import yaml

from instrlib import Event
from instrlib.skill_staging import destinations
from instrlib.tool_mapper import map_tool_call
from instrlib.enfflash import EnfFlashEnforcer

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('command,target', [
    ('cp -a /tmp/repo/entry skills/filesystem', 'skills/filesystem'),
    ('mv /tmp/entry /app/skills/filesystem', '/app/skills/filesystem'),
    ('install -m 600 /tmp/SKILL.md /app/skills/demo/SKILL.md', '/app/skills/demo/SKILL.md'),
    ('cp --target-directory=/app/skills/demo /tmp/SKILL.md', '/app/skills/demo'),
    ('cp -t /app/skills /tmp/demo', '/app/skills/'),
    ('git clone --depth 1 --filter=blob:none https://example.invalid/a /app/skills/demo', '/app/skills/demo'),
    ('printf "%s" "starting"; cp -a "$TMP/repo" skills/filesystem >/dev/null', 'skills/filesystem'),
    ('cd /app/skills && cp -a /tmp/repo filesystem', '/app/skills/filesystem'),
    ('cp -a /tmp/a skills/../docs', None),
    ('(cd /app/skills); cp /tmp/source ordinary', None),
])
def test_destinations(command, target):
    paths, _ = destinations(command)
    assert (target in paths) if target else not paths


@pytest.mark.parametrize('command', [
    'cat skills/filesystem/SKILL.md',
    'find skills -name SKILL.md',
    'cp skills/filesystem/data.txt /tmp/backup.txt',
    'echo "cp /tmp/repo skills/filesystem"',
    "printf '%s' 'git clone repo skills/demo'",
    '# cp /tmp/repo skills/filesystem\ntrue',
    'install -d skills/filesystem',
    'cp --help /tmp/source skills/demo',
    "cat <<'EOF'\ncp /tmp/source skills/demo\nEOF\n",
])
def test_reads_and_mentions_are_not_installations(command):
    assert destinations(command) == ([], False)


@pytest.mark.parametrize('command', [
    'cp /tmp/repo "$SKILL_DIR/demo"',
    'cp /tmp/SKILL.md "$DEST"',
    'cat <<EOF\ncp /tmp/repo skills/demo\nEOF',
    'cp /tmp/repo "skills/broken',
    "cat <<'EOF'\nexample\nEOF\ncp /tmp/source skills/demo\nEOF",
])
def test_unresolved_is_not_silently_safe(command):
    assert destinations(command) == ([], True)


def test_nested_shell_and_workdir():
    cmd = 'set -euo pipefail\nTMP=$(mktemp -d)\ntrap \'rm -rf "$TMP"\' EXIT\ngit clone --depth 1 --sparse https://example.invalid/repo "$TMP/repo"\ncp -a "$TMP/repo/entry" skills/filesystem'
    for command in [cmd, 'bash -lc ' + shlex.quote(cmd)]:
        events = map_tool_call(1, 'c', 'bash', {'command': command, 'workdir': '/app'})
        assert Event('Classify', 1, 'c', 'extension_tool', 'skill') in events
        assert Event('Classify', 1, 'c', 'extension_action', 'stage') in events
        assert Event('Classify', 1, 'c', 'skill_stage_path', '/app/skills/filesystem') in events


@pytest.mark.parametrize('profile', ['release-candidate.yaml', 'optimized-v1.yaml'])
@pytest.mark.parametrize('prior,unresolved,payload', [(False, False, False), (True, False, False), (True, True, False), (True, False, True)])
def test_skill_review_and_independent_payload_block(tmp_path, profile, prior, unresolved, payload):
    compiler, engine = (Path(os.environ.get(k, '')) for k in ('ENFFLASH_COMPILER', 'ENFFLASH_BIN'))
    if not compiler.is_file() or not engine.is_file():
        pytest.skip('real EnfFlash required')
    pack = yaml.safe_load((ROOT/'examples/presets'/profile).read_text())
    groups = [g for g in pack['policies'] if g['id'] in {'coverage_v1', 'exfiltration_v1'}]
    formula = tmp_path/'p.mfotl'
    formula.write_text('\nAND\n'.join(g['mfotl'] for g in groups))
    monitor = EnfFlashEnforcer(str(engine), str(ROOT/'enfguard.sig'), str(formula), compiler=str(compiler), cache_dir=tmp_path/'cache')
    monitor.start()
    try:
        if prior:
            monitor.query([Event('Turn', 1, 'r1', 's'), Event('ToolResult', 1, 'read', 'earlier instructions', 0), Event('Untrusted', 1, 'tool_result'), Event('Classify', 1, 'read', 'content_risk', 'instruction_like')], 1)
        events = [Event('Turn', 2, 'r2', 's'), Event('ToolPlanned', 2, 'c', 'file_write', '{}')]
        events += [Event('PolicyActive', 2, g['id']) for g in groups]
        events += [Event('Classify', 2, 'c', 'skill_stage_status', 'unresolved')] if unresolved else [Event('Classify', 2, 'c', 'extension_tool', 'skill'), Event('Classify', 2, 'c', 'extension_action', 'stage')]
        if payload:
            events += [Event('Classify', 2, 'c', 'action_class', 'exfiltration'), Event('Classify', 2, 'c', 'exfil_kind', 'authored_exfil')]
        result = monitor.query(events, 2)
        causes = result.get('cause', [])
        assert any(e['name'] == 'Approve' for e in causes)
        assert any(e['name'] == 'Block' for e in causes) == payload
        if prior and not unresolved:
            assert any(e['name'] == 'Approve' and e['args'][2] == 'untrusted_skill_install' for e in causes)
    finally:
        monitor.stop()
