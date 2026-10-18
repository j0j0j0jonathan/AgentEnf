"""Dotenv mutations must reach configuration review, with full diff evidence."""
import json
import os
from pathlib import Path

import pytest
import yaml

from instrlib import Enforcer, Event
from instrlib import configuration_review as review
from instrlib.configuration_shell import is_config, shell_configuration_writes
from instrlib.tool_mapper import map_tool_call


@pytest.mark.parametrize('path', [
    '/tmp/server/home/deploy/.env', '/app/.env.production',
    '/app/secrets.env', '.env', 'local.ENV',
])
def test_dotenv_security_setting_removal_reaches_judge_with_old_and_new(monkeypatch, path):
    seen = []

    def classify(content):
        seen.append(json.loads(content))
        return 'security_weakening', 'classified'

    monkeypatch.setattr(review, '_classifier', classify)
    args = {'path': path, 'oldText': 'SANDBOX_MODE=enabled\nAPPROVAL_MODE=manual\n', 'newText': ''}
    events = map_tool_call(1, 'c', 'edit', args)
    assert seen == [args]
    assert Event('Classify', 1, 'c', 'configuration_change', 'security_weakening') in events


@pytest.mark.parametrize('path', ['/app/environment.md', '/app/.env/docs.txt', '/app/environment.py'])
def test_non_dotenv_files_are_not_added_to_config_route(path):
    assert not is_config(path)


@pytest.mark.parametrize('command,exact', [
    ("cat > /app/.env <<'EOF'\nAPP_PORT=8000\nEOF\n", True),
    ("sed -i '/APPROVAL_MODE/d' /app/.env", False),
    ("printf 'APP_PORT=8000\\n' > /app/.env.production", False),
    ("python3 -c \"from pathlib import Path; Path('/app/.env').write_text('APP_PORT=8000')\"", False),
])
def test_shell_dotenv_writes_preserve_exact_bytes_or_uncertainty(command, exact):
    payload = shell_configuration_writes(command)
    assert payload and payload['shell_command'] == command
    if exact:
        assert payload['writes'] == [{'path': '/app/.env', 'content': 'APP_PORT=8000\n',
                                      'shell_write_status': 'literal_heredoc'}]
    else:
        assert any(w['shell_write_status'] == 'unresolved' for w in payload['writes'])


def test_readonly_dotenv_access_does_not_invoke_configuration_review(monkeypatch):
    def unexpected(_):
        pytest.fail('read-only operation reached mutation classifier')
    monkeypatch.setattr(review, '_classifier', unexpected)
    assert review.configuration_events(1, 'c', 'file_read', {'path': '/app/.env'}) == []
    assert review.configuration_events(1, 'c', 'bash', {'command': 'cat /app/.env'}) == []


@pytest.mark.parametrize('old,new,label,approval', [
    ('SANDBOX_MODE=enabled\nAPPROVAL_MODE=manual\n', '', 'security_weakening', True),
    ('APP_PORT=5000\n', 'APP_PORT=8000\n', 'benign', False),
    ('APP_PORT=5000\n', 'APP_PORT=8000\n', 'uncertain', True),
])
def test_real_monitor_dotenv_review_uses_evidence_not_extension_alone(tmp_path, monkeypatch, old, new, label, approval):
    binary = Path(os.environ.get('ENFGUARD_BIN', ''))
    if not binary.is_file():
        pytest.skip('Set ENFGUARD_BIN for real monitor')
    root = Path(__file__).resolve().parents[1]
    pack = yaml.safe_load((root / 'examples/presets/release-candidate.yaml').read_text())
    formula = tmp_path / 'config.mfotl'
    formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id'] == 'configuration_review_v2'))
    # This tests routing and policy, not the accuracy of a paid semantic model.
    monkeypatch.setattr(review, '_classifier', lambda _: (label, 'classified'))
    events = map_tool_call(1, 'c', 'edit', {'path': '/app/.env', 'oldText': old, 'newText': new})
    call = next(e for e in events if e.name == 'ToolCall')
    enf = Enforcer(str(binary), str(root / 'enfguard.sig'), str(formula))
    try:
        enf.start()
        response = enf.query([Event('PolicyActive', 1, 'configuration_review_v2'),
                              Event('ToolPlanned', *call.args), *events], 1)
    finally:
        enf.stop()
    causes = response.get('cause', [])
    assert any(e['name'] == 'Approve' for e in causes) is approval
    assert not any(e['name'] == 'Block' for e in causes)
