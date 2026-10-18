"""Freeze committed runtime and retained runner for a matched development smoke.
No container, model or reserved dataset is opened by preparation.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

from experiments.paper import validation_bundle

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2)+'\n')


def freeze(design, reference, output, reply_replay, property_replay):
    design, reference, output, reply_replay, property_replay = map(Path,
        (design, reference, output, reply_replay, property_replay))
    if subprocess.check_output(['git', 'diff', 'HEAD', '--name-only'], cwd=ROOT).strip():
        raise ValueError('Commit tracked changes before freezing')
    output.mkdir(parents=True, exist_ok=False)
    runtime = output/'runtime'; runtime.mkdir()
    archive = subprocess.check_output(['git', 'archive', 'HEAD'], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(runtime, filter='data')
    retained = json.loads((reference/'frozen-hashes.json').read_text())
    copied = {}
    for name, digest in retained.items():
        if (name.startswith(('harness/', 'contracts/')) or
                ('/' not in name and name.endswith('.py') and name != 'run.py')):
            original = reference/name
            if sha(original) != digest:
                raise ValueError('Retained runner differs: '+name)
            target=output/name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, target); copied[name]=digest
    shutil.copytree(design/'inputs', output/'inputs')
    m=json.loads((design/'manifest.json').read_text())
    for arm in m['arms']:
        if arm['profile']:
            target=output/'profiles'/arm['profile']; target.parent.mkdir(exist_ok=True)
            shutil.copy2(design/arm['profile'], target)
            assert sha(target)==arm['sha256']
    # This smoke deliberately fails on unhealthy runs; no old capacity exemption.
    (output/'run.py').write_text('from pathlib import Path\nimport sys\nP=Path(__file__).resolve().parent\nsys.path.insert(0,str(P/"runtime"))\nfrom experiments.paper.pilot import main\nif __name__ == "__main__": main(P)\n')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    dump(output/'runtime-amendment.json', {'id':'matched-frozen-runtime', 'commit':commit,
         'all_trajectories_same_source':True, 'request_limit':80})
    raw=ROOT.parent/'outputs/paper-targeted-validation-2026-10-15'
    staging=output/'validation-inputs'
    for src, rel in [(reply_replay,'reply-runtime-portable'),(property_replay,'property-runtime-review'),
                     (raw/'reply-fresh/run','reply-fresh/run'),
                     (raw/'semantic-followup/candidate','semantic-followup/candidate')]:
        dst=staging/rel; dst.mkdir(parents=True)
        for name in (('summary.json','results.json') if 'review' in rel or 'portable' in rel else
                     ('manifest.json','cases.json','results.jsonl')):
            shutil.copy2(src/name,dst/name)
    # Validation hashes the archive, not unrelated untracked drafts in the checkout.
    validation_bundle.ROOT=runtime
    validation_bundle.prepare(staging, output/'validation')
    m.update(status='frozen_for_smoke_only', repository_head=commit,
             classifier_backend='openai_decisions',
             validation={'directory':'validation','manifest_sha256':sha(output/'validation/manifest.json')})
    smoke_ids={'seed-0311','syn-0718','seed-0051','syn-0126','seed-0006','syn-0014',
               'seed-0186','seed-0457','seed-0072','seed-0105'}
    assert smoke_ids <= {c['id'] for c in m['cases']}
    m['smoke_schedule']=[r for r in m['schedule'] if r['rep']==1 and r['case'] in smoke_ids]
    assert len(m['smoke_schedule'])==30
    m['smoke_trajectories']=30
    m['full_run_gate']='Review all smoke outcomes, runtime approvals, failures and evidence before full collection.'
    dump(output/'manifest.json',m)
    dump(output/'retained-runner-provenance.json',{'reference':str(reference.resolve()),'source_hashes':copied})
    dump(output/'runtime-hashes.json',{str(p.relative_to(runtime)):sha(p) for p in runtime.rglob('*') if p.is_file()})
    script=output/'01-smoke.command'
    script.write_text('#!/bin/zsh\nset -eu\numask 077\ncd '+shlex.quote(str(output.resolve()))+
        '\nexec caffeinate -i '+shlex.quote(str(ROOT/'.venv/bin/python'))+' run.py --smoke\n')
    script.chmod(0o700)
    dump(output/'frozen-hashes.json',{str(p.relative_to(output)):sha(p) for p in output.rglob('*')
                                   if p.is_file() and '__pycache__' not in p.parts})
    return m


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('design',type=Path);p.add_argument('reference',type=Path)
    p.add_argument('output',type=Path);p.add_argument('reply_replay',type=Path);p.add_argument('property_replay',type=Path)
    a=p.parse_args();m=freeze(a.design,a.reference,a.output,a.reply_replay,a.property_replay)
    print('Frozen',m['smoke_trajectories'],'smoke trajectories; no live runs launched.')
