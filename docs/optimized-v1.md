# optimized-v1: cleanup only

The original lexical exemption experiment was withdrawn on 14 October 2026.
`examples/presets/optimized-v1.yaml` now contains only two changes relative to the
release candidate:

- Remove `provenance_v1:openclaw_private_control_read` (Approve). The more general
  `control_artifact_read` in the **same group** still requests approval. The
  after-untrusted Block is unchanged.
- Correct reconnaissance warning descriptions from “2 minutes” to “10 minutes”.
  Their actual 600-second windows and thresholds are unchanged.

No other rule, threshold, predicate prompt, approval configuration, or group
activation changes. The duplicate credential approval in `discovery_v2` stays,
so disabling `credential_v1` does not silently remove its coverage. Runtime
integration for lexical tokens/risk-lowering facts has been removed. No default
profile is changed and no read-only exemption is active.

Regenerate with `.venv/bin/python experiments/release_candidate/build_optimized.py`.
Tests compare every labelled clause to the source and exercise both packs with the
real monitor. They also retain the cross-group credential clause.

Run `.venv/bin/python -m pytest -q tests/test_optimized_v1_monitor.py`, with
`ENFGUARD_BIN` pointing to the monitor binary. Without it, only the static pack
comparison runs; monitor tests are skipped.

## Why the original exemption was withdrawn

Absence of a lexical match does not establish independence from an instruction.
A harmless-looking `cat /tmp/project/./report.txt` missed a token containing
`/tmp/project/report.txt`. An empty token store could likewise emit a risk-lowering
fact, although observations at the model boundary did not populate that store.

The original 130 -> 94 result mixed historical approvals with a partial current
mapper replay. It was not a full release-candidate-versus-optimized evaluation,
and remaining approvals somewhere in a harmful run did not establish that the
harmful effect was still guarded. Do not cite that result for this cleanup pack.
Original files and results were preserved locally in the audit output. The retired
replay and lexical helper are not dependencies of this cleanup pack or its tests.

## Narrow capability investigation

A separate local investigation measures opportunity and supplies a contract
fixture. It does not emit exemption facts, bypass approvals, or provide an
integrated OpenClaw capability. That experiment is outside this cleanup change.
