"""Protect isolated setup state and cross-boundary session identity."""
import importlib.util
import json
from pathlib import Path
import stat
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def load_script(name, monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_init_preserves_token_and_workspace_and_validates_monitor(tmp_path, monkeypatch):
    q = load_script('quickstart', monkeypatch)
    with pytest.raises(ValueError, match='executable'):
        q.prepare(tmp_path / 'state', str(tmp_path / 'missing'), 9000)
    folder = tmp_path / 'state'
    q.prepare(folder, sys.executable, 19000)
    token = (folder / 'admin-token').read_text()
    assert stat.S_IMODE((folder / 'admin-token').stat().st_mode) == 0o600
    (folder / 'workspace/README.md').write_text('user changes')
    q.prepare(folder, sys.executable, 19001)
    assert (folder / 'admin-token').read_text() == token
    assert (folder / 'workspace/README.md').read_text() == 'user changes'
    assert q.settings(folder)[0]['port'] == 19001


def test_generated_profile_joins_sessions_and_does_not_embed_provider_key(tmp_path, monkeypatch):
    p = load_script('prepare_openclaw', monkeypatch)
    monkeypatch.setenv('OPENAI_API_KEY', 'must-not-be-copied')
    config = p.build_profile(tmp_path, {'port': 19000}, 'local-test-token', 'test-model', 18799)
    provider = config['models']['providers']['openai']
    gate = config['plugins']['entries']['enfguard-gate']['config']
    assert provider['headers']['x-session-id'] == gate['sid']
    assert provider['headers']['x-session-id']
    assert provider['baseUrl'] == gate['apiUrl'] + '/v1'
    assert gate['adminToken'] == 'local-test-token'
    assert 'must-not-be-copied' not in json.dumps(config)
    assert provider['apiKey'] == '${OPENAI_API_KEY}'
    assert config['agents']['defaults']['workspace'] == gate['workspaceRoots'][0]


def test_smoke_check_rejects_wrong_policy_and_unattributed_block(tmp_path, monkeypatch):
    q = load_script('quickstart', monkeypatch)
    q.prepare(tmp_path, sys.executable, 9000)
    monkeypatch.setattr(q, 'get_json', lambda *args, **kw: {'ok': True, 'yaml_file': '/wrong.yaml'})
    with pytest.raises(ValueError, match='different policy'):
        q.check(tmp_path)
    replies = iter([{'ok': True, 'yaml_file': str(q.ROOT / 'examples/quickstart.yaml')},
                    {'decision': 'allow'}, {'decision': 'block'}])
    monkeypatch.setattr(q, 'get_json', lambda *args, **kw: next(replies))
    with pytest.raises(ValueError, match='expected quickstart rule'):
        q.check(tmp_path)
