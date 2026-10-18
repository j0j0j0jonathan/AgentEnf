import json
from pathlib import Path

import pytest
from experiments.paper import pilot
from experiments.paper.calibrate import dump, sha


def test_frozen_pilot_rejects_source_and_binary_changes(tmp_path):
    source = tmp_path / 'run.py'; source.write_text('frozen')
    binary = tmp_path / 'binary'; binary.write_bytes(b'binary')
    dump(tmp_path / 'manifest.json', {'monitor': {'runtime': {'path': str(binary), 'sha256': sha(binary)}}})
    dump(tmp_path / 'frozen-hashes.json', {'run.py': sha(source)})
    assert pilot.check(tmp_path)['monitor']
    source.write_text('changed')
    with pytest.raises(ValueError, match='source changed'):
        pilot.check(tmp_path)
    source.write_text('frozen'); binary.write_bytes(b'changed')
    with pytest.raises(ValueError, match='Monitor binary'):
        pilot.check(tmp_path)


def test_integrated_validation_gate_rejects_changed_code_or_evidence(tmp_path):
    import importlib.metadata
    from experiments.paper.validation_bundle import check
    runtime = tmp_path / 'runtime'; runtime.mkdir()
    source = runtime / 'classifier.py'; source.write_text('frozen implementation')
    evidence = tmp_path / 'validation'; evidence.mkdir()
    record = evidence / 'results.json'; record.write_text('{"cases": 30}')
    manifest = {'schema': 'candidate-validation-v1',
                'source_hashes': {'classifier.py': sha(source)},
                'evidence_hashes': {'results.json': sha(record)},
                'parser_version': importlib.metadata.version('markdown-it-py')}
    dump(evidence / 'manifest.json', manifest)
    assert check(evidence, runtime) == manifest
    source.write_text('changed implementation')
    with pytest.raises(ValueError, match='runtime changed'):
        check(evidence, runtime)
    source.write_text('frozen implementation'); record.write_text('{"cases": 31}')
    with pytest.raises(ValueError, match='evidence changed'):
        check(evidence, runtime)


@pytest.mark.parametrize('component,key', [('runtime', 'ENFFLASH_BIN'), ('compiler', 'ENFFLASH_COMPILER')])
def test_validation_uses_replayed_monitor(component, key):
    from experiments.paper.validation_bundle import check_monitor
    validation = {'monitor_hashes': {'ENFFLASH_BIN': 'runtime-hash', 'ENFFLASH_COMPILER': 'compiler-hash'}}
    monitor = {'runtime': {'sha256': 'runtime-hash'}, 'compiler': {'sha256': 'compiler-hash'}}
    check_monitor(validation, monitor)
    monitor[component]['sha256'] = 'different-build'
    with pytest.raises(ValueError, match=component):
        check_monitor(validation, monitor)


def test_explicit_smoke_does_not_launch_entire_first_repetition():
    rows = [dict(case=f'case-{i}', arm=arm, rep=1) for i in range(100)
            for arm in ['off', 'strict', 'permissive']]
    manifest = {'schedule': rows, 'smoke_schedule': rows[:6]}
    assert len(pilot.select_schedule(manifest)) == 6
    assert len(pilot.select_schedule(manifest, full=True)) == 300
    manifest['smoke_schedule'] = [dict(case='unknown', arm='off', rep=1)]
    with pytest.raises(ValueError, match='subset'):
        pilot.select_schedule(manifest)
