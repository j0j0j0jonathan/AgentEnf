import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

import proxy
from instrlib import tool_judge, tool_mapper
from instrlib.property_contracts import VERSION, VALUE_CRITERION, FLOW_CRITERION
from yaml_loader import IngestJudgeConfig, _parse_ingest_judges


def test_only_candidate_profiles_select_calibrated_property_contract():
    root = Path(__file__).resolve().parents[1]
    for filename in ('release-candidate', 'optimized-v1'):
        pack = yaml.safe_load((root / f'examples/presets/{filename}.yaml').read_text())
        assert _parse_ingest_judges(pack['backend']['ingest_judges'], True).property_contract == VERSION
    assert _parse_ingest_judges({}, True).property_contract == ''
    with pytest.raises(ValueError, match='property_contract'):
        _parse_ingest_judges({'property_contract': 'typo'}, True)


def test_hot_reload_binds_and_restores_original_prompts(monkeypatch):
    seen = []
    monkeypatch.setattr(tool_judge, '_ENABLED', tool_judge._ENABLED)
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE', '1')
    monkeypatch.setattr(tool_judge, '_dispatch', lambda adapter, content, timeout, criterion:
                        seen.append((adapter, criterion)) or json.dumps({'label': 'benign'}))
    config = IngestJudgeConfig(property_contract=VERSION)
    monkeypatch.setattr(proxy.state, 'ingest_judges', config)
    proxy._configure_ingest_judges()
    for fn in (tool_mapper._CONTENT_DISCLOSURE_JUDGE, tool_mapper._AUTHORED_CAPABILITY_JUDGE):
        assert fn('fixture input') == (None, 'no_match')
    assert [s[1] for s in seen] == [VALUE_CRITERION, FLOW_CRITERION]
    monkeypatch.setattr(proxy.state, 'ingest_judges', replace(config, property_contract=''))
    proxy._configure_ingest_judges()
    tool_mapper._CONTENT_DISCLOSURE_JUDGE('fixture input')
    tool_mapper._AUTHORED_CAPABILITY_JUDGE('fixture input')
    assert [s[1] for s in seen[-2:]] == [tool_judge._CONTENT_DISCLOSURE_SYSTEM_PROMPT,
                                       tool_judge._AUTHORED_CAPABILITY_SYSTEM_PROMPT]
    monkeypatch.setattr(proxy.state, 'ingest_judges', replace(config, enabled=False))
    proxy._configure_ingest_judges()
    assert tool_mapper._CONTENT_DISCLOSURE_JUDGE is None
    assert tool_mapper._AUTHORED_CAPABILITY_JUDGE is None


@pytest.mark.parametrize('fn,criterion', [
    (tool_judge.classify_content_disclosure_with_status, VALUE_CRITERION),
    (tool_judge.classify_authored_capability_with_status, FLOW_CRITERION),
])
def test_candidate_adapters_keep_failure_status_and_full_input(monkeypatch, fn, criterion):
    monkeypatch.setenv('ENFGUARD_TOOL_JUDGE', '1')
    seen = []
    def fail(adapter, text, timeout, prompt):
        seen.append((text, prompt))
        raise ValueError('transport failure')
    monkeypatch.setattr(tool_judge, '_dispatch', fail)
    content = 'Grüße "secret" \\n' * 1000
    assert fn(content, criterion=criterion) == (None, 'failed_open')
    assert content in seen[0][0] and seen[0][1] == criterion
