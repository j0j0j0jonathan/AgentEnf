"""Build the cleanup-only opt-in pack; never remove an approval checkpoint.

The original lexical exemption experiment is withdrawn. Thresholds and
cross-group credential coverage are preserved. No default profile is changed.
"""
import copy
import hashlib
import re
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'examples/presets/release-candidate.yaml'
OUT = ROOT / 'examples/presets/optimized-v1.yaml'
LABEL = re.compile(r'\{"([^"\n]+)"\}\s*\{')


def clauses(text):
    matches = list(LABEL.finditer(text))
    return [(m.group(1), re.sub(r'\s*AND\s*$', '', text[m.start():matches[i+1].start() if i+1 < len(matches) else None]).strip())
            for i, m in enumerate(matches)]


def build(source=SRC, target=OUT):
    pack = copy.deepcopy(yaml.safe_load(source.read_text()))
    for group in pack['policies']:
        text = group['mfotl']
        if group['id'] == 'provenance_v1':
            rows = clauses(text)
            assert sum(name == 'openclaw_private_control_read' for name, _ in rows) == 1
            removed = next(body for name, body in rows if name == 'openclaw_private_control_read')
            assert 'IMPLIES:R Approve(' in removed
            assert any(name == 'control_artifact_read' for name, _ in rows)
            text = '\n\nAND\n\n'.join(body for name, body in rows if name != 'openclaw_private_control_read')+'\n'
        if group['id'] == 'reconnaissance_v1':
            # Only the human-readable explanation changes. The interval already is 600 s.
            text = text.replace('within the last 2 minutes', 'within the last 10 minutes')
        group['mfotl'] = text
    pack['meta'] = {**pack.get('meta', {}), 'name': 'optimized-v1-cleanup', 'base_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                    'note': 'Cleanup only. Lexical approval exemption withdrawn. No thresholds, Blocks, or cross-group coverage changed.'}
    target.write_text('# Cleanup only; original lexical exemption withdrawn. Opt-in, not a new default.\n'
                      + yaml.safe_dump(pack, sort_keys=False, width=1000))
    return pack


if __name__ == '__main__':
    build()
    print(OUT)
