Pinned live experiment (19 October 2026)
--------------------------------------
install.py and guidance.js implement an opt-in prompt-builder patch for the exact
OpenClaw 2026.3.12 image recorded in pinned-bundles.json. The installer runs before
container start, verifies all six original bundle hashes, and patches every copy
of buildBootstrapContextFiles. pilot.py enables it only when the frozen manifest
sets startup_guidance=full-supplied-only-v1, identically in OFF and ON.

After the original per-file and total budgets, compare each supplied file with
its loader snapshot (using OpenClaw's trimEnd normalization). Only fully supplied
SOUL.md, USER.md and MEMORY.md get a shorter use-supplied instruction in the exact
AGENTS.md startup paragraph. AGENTS.md itself must be fully supplied. Daily memory,
missing and truncated files retain reads. No workspace file, other context body,
policy or tool authorization changes. No budget is redistributed after shortening.
Unknown templates stay unchanged. Changes emit metadata to container stderr;
no file content is logged by the patch. This is guidance, not an authenticated
read grant, and the model may still reread. Source snapshots may be cached by
OpenClaw; full means fully supplied in this prompt, not freshest on-disk bytes.

This is a deviation from default A3S. The offline tests prove prompt assembly and
content preservation, not unchanged agent behaviour or improved attack outcomes.
Review before/after denials by rule and repeated reads. Include an unchanged-
guidance OFF control for the memory attack alongside treatment OFF. A lower OFF
attack rate may be a harness effect; one repetition cannot establish causality.
No live API test has been launched yet.

The older Python assembly.py prototype below is NOT the installed implementation.
In particular, its confirmed-absence optimization is NOT enabled by guidance.js.

Startup-context experiment — offline only
========================================

Purpose
OpenClaw's recorded Project Context already supplies several private workspace
files, while AGENTS.md still instructs the model to read those files at startup.
Remove that redundant instruction instead of bypassing approval policies.

Status
assembly.py is a pure prompt-assembly prototype, not installed in OpenClaw and
not imported by the proxy or gate. No live profile, policy formula, classifier,
event signature or permission decision changes. The returned context differs
only in the exact recognized Session Startup paragraph of AGENTS.md. First-run
onboarding and every other file body remain unchanged.

Contract being tested
- The loader/prompt builder supplies observations for this namespace, session,
  request, workspace and local calendar day. Full and truncated observations
  carry a file version and a hash of the exact supplied text.
- Full supplied context can replace a read performed solely for startup.
- Confirmed absence must be an explicit loader observation. No Project Context
  section means UNKNOWN, not absent. Unknown/truncated resources retain reads.
- A fresh request requires a fresh receipt. Changed supplied text rejects an
  old hash. Guidance explicitly permits fresh reads through normal tool checks.
- Same basenames, textual 'origin=startup' claims, or a file saying 'absent'
  cannot populate the observation structure. No such structure is accepted
  from model or tool input in this prototype because it has no runtime endpoint.
- The assembler fails on an unfamiliar AGENTS startup template. A future opt-in
  adapter should leave the original prompt unchanged and report unsupported
  guidance, rather than silently rewrite arbitrary instructions.

Trust and limitations
These Python data classes are NOT an attestation format. Anyone calling this
offline function can construct them. No production path may trust a receipt
from an agent, user message, tool arguments, or arbitrary plugin metadata.
Canonical spelling validation does not resolve a symlink or verify a live file.
That requires a runtime loader integration with safe file opening, identity and
version capture, explicit ENOENT versus permission/error handling, and final
prompt truncation accounting. A request identifier must not be reused.
The current code tests hash consistency and request isolation, not that a file
has remained unchanged on disk since the loader read it.

Loading a memory file does not make its contents safe. In particular, the tests
deliberately preserve malicious memory content, so they cannot demonstrate that
memory poisoning or disclosure is prevented. Model-requested rereads, writes,
outputs and outbound tools still need the existing enforcement. If a file must
never reach the model, enforce at loading or before forwarding the request.

Tests (run from repository root)
.venv/bin/python -m pytest -q tests/test_startup_context.py

The workspace's outputs/trusted-startup-review-2026-10-14 contains the audit,
historical-panel verification, prompt-only replay and proposed live comparison.
The replay uses SYNTHETIC receipts and confirms template compatibility only;
it must not be described as an authenticated startup integration or an observed
reduction in tool calls. It adds prompt text, so token savings are unmeasured.
