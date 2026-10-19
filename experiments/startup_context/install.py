"""Pinned, opt-in benchmark prompt patch; no policy exemption or workspace edits."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
from experiments.startup_context.assembly import ORIGINAL_STARTUP

ROOT = Path(__file__).parent
MARKER = 'function buildBootstrapContextFiles(files, opts) {'
END = '\n\treturn result;\n}'

def patch(source):
    if source.count(MARKER) != 1:
        raise ValueError('Unknown bootstrap builder')
    start = source.index(MARKER)
    end = source.index(END, start)
    helper = (ROOT/'guidance.js').read_text().replace('__ORIGINAL_STARTUP__', json.dumps(ORIGINAL_STARTUP, ensure_ascii=True))
    return source[:start] + helper + '\n' + source[start:end] + '\n\treturn agentEnfStartupGuidance(files, result);\n}' + source[end+len(END):]

def install(container_id, report):
    """Patch all known bundle copies before container start; reject other images."""
    manifest = json.loads((ROOT/'pinned-bundles.json').read_text())
    changed = []
    stream = io.BytesIO()
    # Read/validate everything before writing any bundle.
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, digest in manifest['bundles'].items():
            data = subprocess.run(['docker','cp',f'{container_id}:/app/dist/{name}','-'], check=True, capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(data)) as incoming:
                members = [m for m in incoming.getmembers() if m.isfile()]
                if len(members) != 1: raise ValueError('Unexpected Docker archive')
                raw = incoming.extractfile(members[0]).read()
            if hashlib.sha256(raw).hexdigest() != digest: raise ValueError('Pinned OpenClaw bundle changed: '+name)
            updated = patch(raw.decode()).encode()
            info = tarfile.TarInfo(name); info.mode = 0o644; info.size = len(updated)
            archive.addfile(info, io.BytesIO(updated))
            changed.append({'file':name,'before':digest,'after':hashlib.sha256(updated).hexdigest()})
    subprocess.run(['docker','cp','-',f'{container_id}:/app/dist/'],input=stream.getvalue(),check=True,capture_output=True)
    Path(report).write_text(json.dumps({'version':1,'openclaw':manifest['openclaw'],'changed':changed,
      'deviation':'Only redundant startup reads for fully supplied files; daily memory unchanged; no read allowance.'},indent=2))
