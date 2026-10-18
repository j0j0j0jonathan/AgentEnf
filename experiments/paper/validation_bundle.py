"""Freeze inspected calibration + runtime replay evidence for the next pilot.

This gate is a development check, not an independent accuracy certification.
It permits the integrated strategy with the inspected reply and 20 property
cases; it never marks a changed implementation calibrated by default.
"""
import importlib.metadata
import json
from pathlib import Path
import shutil

from experiments.paper.calibrate import dump, sha

ROOT = Path(__file__).resolve().parents[2]


def source_hashes(root):
    paths = [p for p in root.iterdir() if p.is_file() and p.suffix in {'.py', '.sig', '.mfotl', '.toml'}]
    for folder in ('instrlib', 'experiments/paper', 'integrations/openclaw/enfguard-gate'):
        paths.extend(p for p in (root / folder).rglob('*') if p.is_file() and p.suffix in {'.py', '.js', '.json'})
    paths.extend(root / 'examples/presets' / name for name in ('release-candidate.yaml', 'optimized-v1.yaml'))
    return {str(p.relative_to(root)): sha(p) for p in paths if '__pycache__' not in p.parts}


def prepare(source, output, *, reply_followup=None, reply_report=None, property_report=None):
    source, output = Path(source), Path(output)
    reports = {'reply': source / 'reply-runtime-portable', 'properties': source / 'property-runtime-review'}
    raw = {'reply': source / 'reply-fresh/run', 'properties': source / 'semantic-followup/candidate'}
    reply_count = 30
    if (reply_followup is None) != (reply_report is None):
        raise ValueError('A follow-up requires both fresh answers and their integration replay')
    if reply_followup is not None:
        from experiments.paper.calibrate_pilot_replies import check as check_followup
        checked = check_followup(reply_followup)
        assert checked['cases'] == 44 and checked['pilot_allow_labels'] == 14 and checked['security_controls'] == 30
        reply_count = 44
        raw['reply'] = Path(reply_followup) / 'run'
        reports['reply'] = Path(reply_report)
    if property_report is not None:
        reports['properties'] = Path(property_report)
    for name, report in reports.items():
        summary = json.loads((report / 'summary.json').read_text())
        expected = reply_count if name == 'reply' else 20
        assert summary['cases'] == summary['agreements'] == expected and summary['new_api_calls'] == 0
        if name == 'reply' and reply_followup is not None:
            assert summary['calibration_results_sha256'] == sha(raw[name] / 'results.jsonl')
        for file, digest in summary['source_hashes'].items():
            assert sha(ROOT / file) == digest, file
        rows = json.loads((report / 'results.json').read_text())
        cases = json.loads((raw[name] / 'cases.json').read_text())['cases']
        results = [json.loads(line) for line in (raw[name] / 'results.jsonl').read_text().splitlines()]
        assert len(rows) == len(cases) == len(results) == expected
        assert len({c['id'] for c in cases}) == expected
        for case, result, replay in zip(cases, results, rows, strict=True):
            assert case['id'] == result['id'] == replay['id']
            assert result['status'] == 'ok' and result['label'] == case['expected']
            if name == 'reply':
                assert replay['blocks'] == (['harmful_command_output'] if case['expected'] else [])
            else:
                assert replay['label'] == case['expected']
    output.mkdir(parents=True, exist_ok=False)
    for name in reports:
        dest = output / name; dest.mkdir()
        for filename in ('summary.json', 'results.json'):
            shutil.copy2(reports[name] / filename, dest / filename)
        for filename in ('manifest.json', 'cases.json', 'results.jsonl'):
            shutil.copy2(raw[name] / filename, dest / ('calibration-' + filename))
    if reply_followup is not None:
        shutil.copy2(Path(reply_followup) / 'experiment.json', output / 'reply/followup-experiment.json')
    manifest = {'schema': 'candidate-validation-v1', 'model': 'gpt-6-luna', 'backend': 'openai_decisions',
                'reply_cases': reply_count, 'property_cases': 20, 'parser_version': importlib.metadata.version('markdown-it-py'),
                'monitor_hashes': json.loads((reports['reply'] / 'summary.json').read_text())['monitor_hashes'],
                'source_hashes': source_hashes(ROOT),
                'evidence_hashes': {str(p.relative_to(output)): sha(p) for p in output.rglob('*') if p.is_file()},
                'claim': 'selected development calibration and offline integration checks; live pilot still required'}
    dump(output / 'manifest.json', manifest)
    return manifest


def check_monitor(manifest, monitor):
    """Use the actual compiler/runtime exercised by the integration replay."""
    for key, component in [('ENFFLASH_BIN', 'runtime'), ('ENFFLASH_COMPILER', 'compiler')]:
        if manifest.get('monitor_hashes') and manifest['monitor_hashes'][key] != monitor[component]['sha256']:
            raise ValueError('Validated monitor differs from pilot: ' + component)


def check(directory, runtime):
    directory, runtime = Path(directory), Path(runtime)
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest.get('schema') != 'candidate-validation-v1':
        raise ValueError('Unknown validation evidence schema')
    for name, digest in manifest['evidence_hashes'].items():
        if sha(directory / name) != digest:
            raise ValueError('Validation evidence changed: ' + name)
    for name, digest in manifest['source_hashes'].items():
        if sha(runtime / name) != digest:
            raise ValueError('Validated runtime changed: ' + name)
    if importlib.metadata.version('markdown-it-py') != manifest['parser_version']:
        raise ValueError('Validated Markdown parser changed')
    return manifest
