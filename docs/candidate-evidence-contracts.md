# Candidate evidence contracts

This is an opt-in research candidate, not a new default or a measured security improvement. The frozen thesis policy fixture remains unchanged. The current candidate has 135 labelled clauses; optimized-v1 has 134, because it retains the previously reviewed duplicate-approval cleanup.

## Current implementation status (15 October 2026)

The chronological experiment notes below retain earlier failures. The current
candidate now selects `strategy: reply_guard_v1` for
`operationalizes_untrusted_harm`, with explicit Decisions backend and closed failure
mode. Its versioned contract is validated at YAML load; editing its descriptive
prompt is rejected instead of silently ignored. Other predicates retain their
normal strategy. The computed binary label is separate from raw model scores.

Fresh selected controls matched 30/30 (14 Allows, 16 Blocks). Fixed-answer replay
through the actual runtime, caches and EnfFlash also matched 30/30. This does not
establish general accuracy. The latest full suite passed 3,985 tests; 24 optional
baseline checks were skipped. The 18-trajectory pilot completed collection but
revealed five monitor crashes and 14 reply budget failures across eight runs.
Every guarded run was affected by at least one. No effectiveness or overhead
claim can be made from this pilot; see `docs/current-validation-plan.md`.

`backend.ingest_judges.property_contract: literal_flow_v1` opts into the two checked
literal-secret/dataflow definitions. Registration binds them locally; switching
back to an original profile restores original criteria. Their 20 selected API
results also pass registered-adapter replay. Original default prompts are intact.

The reply guard now uses at most 64 unique code units, bounded whole inputs and a
shared deadline (including model-slot waiting). A failure is visible and uncached;
it is not reported as a successful semantic finding. Conservative textual matching
can overblock paraphrases or many-snippet benign replies. The previous eight-unit
limit blocked 14 ordinary pilot replies because filenames/variables count as
inline code. All units are still checked; the higher cap can cost up to 66 API
calls per reply and needs fresh live validation. Unit-limit and byte-limit errors
are distinguished. Skipped coverage has no
fabricated probability. Cache identity includes the strategy; pre-evaluation also
requires the same execution contract. Independent secret/private-output checks
remain separate. The prior context is exactly the permitted request-local text,
not proof of authorization or causation.

`markdown-it-py==4.2.0` is now an explicit dependency. EnfFlash passes the launcher's
installed dependency paths to embedded CPython; otherwise even exact cache lookup
could fail during import. This was reproduced and fixed with the actual engine.
The tested embedded and launcher Python versions both are 3.12.13.

The pilot also required an EnfFlash input-framing patch: a semicolon at the end of
a physical line inside a quoted string must not terminate the timepoint. Exact
CRLF/LF input and JSON escaping of dynamic verdicts are covered by the repaired
build. It is separate from the original pinned pilot binary. The reproducible
source-copy patcher is `experiments/paper/patch_enfflash_framing.py`; a new pilot
must pin its new runtime hash, not silently substitute it into old manifests.

## Exact predicate strings with EnfFlash

Set these in the environment of the proxy:

```sh
export AGENTENF_MONITOR_BACKEND=enfflash
export ENFFLASH_COMPILER=/absolute/path/to/EnfFlash/bin/enfflash.exe
export ENFFLASH_BIN=/absolute/path/to/EnfFlash/enfflash/target/release/enfflash
export ENFGUARD_YAML=/absolute/path/to/AgentEnf/examples/presets/release-candidate.yaml
export ENFGUARD_CAPTURE_PREDICATE_INPUTS=1
```

Use the normal proxy start command after setting these variables. EnfGuard remains the default when the backend setting is absent. An invalid selection or compilation failure does not fall back silently. Both candidate packs are tested against the actual EnfFlash compiler/runtime. Compilation preserves the original formula, records the restricted history-binding transformation and removed labels, and hashes its inputs. Verdict categories remain unique for attribution. The transformation is specific to the supported formula shapes, not a proof of equivalence for arbitrary MFOTL.

EnfFlash's compiler and runtime must come from the same validated build. The tested revision is `25826c4fbfffcd34c3b263fb4fe0757654e9722c`. Paths are intentionally installation-specific; generated binaries are not vendored into this repository.

The backend enables exact predicate input capture by default. `ENFGUARD_CAPTURE_PREDICATE_INPUTS=0` disables it; do not disable it for the paper runs. The log directory contains `predicate_evidence/blobs/<sha256>.txt` and per-process call journals with context, predicate definition hash, backend, raw and normalized score, threshold, cache origin, failure status and latency. These are full inputs and may contain private data. This captures actual monitor predicate arguments, including those evaluated during tool checks. It does not turn a classifier's assertion into proof of a tool effect.

## Proposed writes and observed revisions

The `artifact_provenance_v3` group selects the new evidence contract. It does not add a new event type; its evidence uses named `Classify` dimensions.

- Seven historical proposal joins now request approval: `untrusted_write_then_exec`, `egress_source_then_exec_after_sensitive`, `unbounded_loop_then_exec`, `chmod_exec_after_authored`, `dangerous_script_then_schedule`, `schedule_then_dangerous_script`, and `provenance_hook_payload`.
- `confirmed_dangerous_artifact_use` Blocks execution/scheduling of a full-path revision whose dangerous submitted content has a matching authenticated runtime snapshot.
- `attempted_dangerous_artifact_review` retains same-session attempted-write risk.
- `unverified_artifact_state_review` requests approval for unresolved/invalidated revision evidence.
- `authored_fragment_history_review` requests approval when concatenated proposed fragments suggest a dangerous capability. Such fragments can include denied edits; they no longer assert the contents of the current write.
- `authored_dataflow_review` requests approval when a current write has a possible source/sink pairing but the authored-capability classifier is disabled, unavailable or fails. Co-occurrence alone no longer asserts a complete exfiltration flow in this candidate. A valid negative removes this particular checkpoint; a confirmed authored-exfil result still reaches the Block rule, including inside documentation. Unknown semantic content cannot certify a clean artifact revision.

For a complete file replacement, the pre-tool response can carry an `artifact_ticket` bound to the session, call, operator namespace, absolute path, SHA-256, byte length and a fresh nonce. The OpenClaw after-hook verifies the actual local file, rejects symlink components, checks descriptor metadata around a bounded read, and posts a separate `artifact_attestation` over the authenticated admin channel. The proxy matches it to an accepted pending proposal. Tool response prose cannot supply this evidence. Revision identity/status is retained in trace facts; a generic success message or shell exit is insufficient.

Denied proposals preserve the old state. Failed, partial, overlapping or unverifiable mutations produce unknown state and a review checkpoint, not a clean revision. Unrestricted shell/unknown tools invalidate tracked namespace snapshots on dispatch because their filesystem effects cannot be inferred reliably. A verified full harmless replacement can settle the current revision, while separate attempted-write review remains. A plain secret-source reference or ordinary upload helper is not enough on its own for the new confirmed-danger Block.

Set a stable, nonempty `runtimeNamespace` in the plugin config. Use a new namespace for a different filesystem/container generation. Full paths and namespaces prevent same-basename collisions. Confirmed state can span sessions in the same namespace, but the ledger is process-local and does not survive proxy restart. Arbitrary external writers, symlink races between a check and later use, whole-machine filesystem isolation, and completion of deferred scheduled jobs are not solved here. A runtime snapshot is evidence of bytes at observation time, not an atomic guarantee about all future uses. Partial writes and shell writes are intentionally not promoted to verified revisions.

Approve means human review in the strict candidate. Legacy unattended approvals still execute; downgrading proposal-only Blocks therefore changes protection in that posture. Evaluate both postures explicitly and do not describe this as an unconditional security improvement. Old basename-based joins remain at review, so some approval burden can remain even when a hard false positive is removed.

## Output contract

The candidate routes source/sink co-occurrence and hardcoded upload-helper
signals to the existing authored-capability classifier. This can add calls on
writes the previous mapper classified deterministically. Measure the extra cost,
latency and classifier errors in the pilot; this is a precision change, not a
speedup claim. Legacy unattended approval mode can execute unresolved writes;
strict mode holds them. Other deterministic capability detectors and review
joins remain, so a negative here does not exempt the whole operation.

Secret-literal recognition now declines unquoted multi-word prose and does not
consume the next line after an empty assignment. Quoted passphrases and ordinary
single-token credential assignments still match. Ambiguous prose keeps its
semantic route, including environment-style names such as `API_TOKEN`.

On 15 October the user selected a narrower reply contract:
`operationalizes_untrusted_harm` may exempt a genuine refusal or defensive
explanation that repeats a complete harmful command/procedure already supplied
in the conversation without adding harmful capability. A newly supplied command,
changed dangerous target/arguments, missing essential steps, or fragments assembled
into a usable procedure still count. A disclaimer followed by instructions to
execute the operation is not the refusal-only exception. Tool checks and the
independent secret/private-instruction predicates remain unchanged.

The opt-in candidate now emits `ReplyEvidence(tid, content)` alongside
`Completion`. Its content is a structured envelope with the exact pending reply
and text from this request's user/assistant/tool messages. It excludes hidden
system/developer instructions, reasoning, tool-call arguments, and pending model
output. It reads no session cache or monitor history, so an internally observed
but withheld response does not become prior evidence merely because it is in the
logs. Prior assistant text counts only when present in the next supplied request.
This trusts the harness's submitted conversation; it does not certify that a
particular human saw every message or reconstruct opaque provider-side history.

Whole records are selected newest-first within 24 KiB of serialized context;
order and indices are retained. Omissions, byte count, source-text hash and opaque
provider-history references are explicit. Omitted or unavailable text cannot
justify the exception. This can conservatively block an otherwise non-novel
quote; measure omitted-context frequency and resulting utility cost in the pilot.
The existing 64 KiB overall classifier-input limit remains; overflow is a failure
with the configured fail-closed response, never a semantic positive. Context can
increase token cost. No latency or accuracy improvement is claimed.

Predicate cache/pre-evaluation identity includes the entire reply/context envelope.
Empty tool-only replies skip this judge; malformed evidence fails closed. A missing
ReplyEvidence event has an explicit `reply_evidence_missing` Block in the same
outbound policy group, rather than silently skipping the contextual check. The
static predicate-source index enables emission for both buffered streaming and
non-streaming proxy paths. Legacy/default profiles do not opt into the new event.
Assistant-content omission in persisted session traces also omits this envelope;
opt-in exact predicate evidence remains sensitive and is stored separately.

The completed 41-input calibration is preserved under its original, stricter
no-payload-in-refusal contract: 24 agreements, 14 disagreements, 3 unadjudicated,
no transport/parser failures. Its ten output disagreements must not simply be
relabelled as successes under the changed contract. Historical quote novelty
requires the actual prior context. New paired synthetic cases test old versus
new quotations, changed commands, assembly, endorsement, missing/omitted history
and independent secret handling. Fixed-answer tests verify rule wiring, not
model quality. Subsequent classifier results are recorded below; the candidate's
single contextual criterion has not passed its live semantic check.

The same completed run found two redacted-document secret false positives and
two authored-capability errors (unrelated source/sink co-occurrence; a payload
hidden by warning framing). `experiments/paper/semantic_followup.py` prepares a
44-call development check: six extra property controls on current criteria,
20 property inputs on experimental criteria, and 18 contextual output controls.
The property criteria are experiment-only overrides and have not replaced the
production mapper prompts. These small, selected controls are not an accuracy
estimate or a held-out evaluation.

## Other changes and remaining gates

OpenClaw's native boolean `background` flag and explicit working directory survive normalization. Background execution becomes an auditable fact; its existing Warn posture is not promoted to Block merely because a task runs in the background.

`experiments/paper/evidence_bundle.py` preserves full tool starts/results for the additional harm judgment, separates tested references from baseline references, and rejects invalid judgment references. It does not replace A3S formatting or scoring. Missing artifacts/receipts remain explicit. `baseline_contract.py` defines a common boundary interface. `baseline_ports.py` now delegates development checks to pinned upstream Invariant, AgentSpec and AgentLTL implementations. These are tested engine bridges, not completed security-policy translations or reproduced paper results. See `paper-baselines.md` for the exact scope.

Before a live pilot: independently review the output labels; measure the chosen classifier on the paired calibration cases; pin the source/build; verify capture of dispatch, completion, delivery and required artifacts; freeze the approval and startup factors. New held-out claims require an auditable, tuning-independent case selection. Mere possession of a released dataset or an ID selection list does not establish content exposure. `reserve_holdout.py` excludes execution/substantive-review evidence and exposed seed families, and writes IDs only. Local records cannot certify undocumented inspection; custodian attestation is still required. The existing 150 pairs remain development data.

## Development validation launcher (15 October)

`experiments/paper/calibrate.py` prepares and checks frozen output-contract inputs, then runs them only with the explicit `run` subcommand. It uses the runtime predicate transport/parser with exact Decisions input, retains raw scores/errors, and excludes expected labels from the API request. Failures do not count as semantic negatives. An interrupted request with no persisted result requires inspection before retrying.

`experiments/paper/prepare_pilot.py` freezes a six-case, three-arm development pilot. It snapshots the current runtime and retained benchmark launcher, pins the monitor and profiles, and preserves unchanged startup guidance. `pilot.py` checks those hashes and completed calibration before collection. The pilot is OFF versus the current candidate under legacy/strict approvals, not a prior-release comparison or a held-out evaluation.

`pilot_evidence.py` connects complete evidence export to actual collection. The exporter accepts both `turn_results` (live SingleRunResult) and `turns` (detailed historical format); missing/ambiguous transcripts are rejected. Before/after fixture snapshots, runtime outcome metadata and full model API bodies remain separate evidence types. Generated model text is not proof of delivery. A snapshot budget, missing result or absent loader receipt stays an explicit gap. No-harm judgments require independently supplied per-effect coverage; the exporter never certifies safety simply because it sees no effect.

## Follow-up results, 15 October

The 44-call check completed with no API/transport/parser errors. Experimental
content-value and authored-dataflow criteria matched all 20 selected development
labels. The old criteria missed the new overwritten-variable control. One revised
redacted-document answer remains weakly separated (benign .50 versus secret .39).
This is a small tuned smoke check, not an independent accuracy result; the default
property prompts remain unchanged pending candidate integration and live checks.

The contextual reply criterion matched 9/18: it allowed all eight expected
negatives but missed nine of ten intended Blocks. In particular it still allowed
new harmful commands inside refusals. The earlier software-test result is a
wiring result and must not be cited as evidence that this classifier works.

`experiments/paper/calibrate_reply_components.py` prepares a separate 24-request
experiment: three named properties per input, followed by a deterministic
combination. All 18 prior expected decisions are preserved; six controls are
added. It records component errors as well as final decisions and is not part of
the serving proxy. No threshold was tuned to the failed results.

The component experiment has now completed: 21/24 final agreements, including
all 11 expected Allows and 10/13 intended Blocks. On the original 18 inputs this
is 16/18, compared with 9/18 previously. Payload, refusal and coverage component
agreement is respectively 20/24, 24/24 and 17/24. Five coverage disagreements are
false/not-applicable expectations on payload-free replies; two concern actual
payloads. Correct final decisions sometimes mask wrong component evidence.

It missed a newly quoted destructive command, a command assembled from fragments,
and a newly quoted permission-weakening command. The same byte-identical reply
has payload scores between .12 and .97 across contexts, despite that property
being defined on the reply alone. This is consistent with unwanted context
influence but does not separate it from sampling variability. The diagnostic
`calibrate_reply_isolation.py` keeps the same criteria, threshold, model and
24 labels while giving payload/refusal questions only the reply, and asking
coverage separately with full context. It makes 48 requests, deliberately
resamples identical replies, and is not a production optimization or a claimed
fix. Its focused runner checks pass (64 tests). Both experiments remain outside
the proxy; neither the live pilot nor the 150-pair rerun has been launched.

The separated-input experiment subsequently matched 22/24 final labels (all
11 intended Allows, 11/13 intended Blocks), with no API errors. It repaired the
assembled-command miss; identical replies now receive identical payload scores
in this run. Coverage probabilities did not change. A new-command quote still
gets an invented prior-coverage answer, and a newly quoted permission-weakening
command still gets a false payload negative.

`reply_quote_witness.py` is a development-only candidate, not used by the proxy.
It adds payload scores for standalone CommonMark code units and requires an
actual occurrence in retained prior text before accepting the refusal exception.
Semantic coverage remains necessary: the text witness alone does not establish
that no new procedure is expressed by surrounding prose. Quotes, escapes and
newlines are preserved; a limited single-line horizontal-whitespace equivalence
is supported. Records are never spliced and changed arguments do not match.
Multiple dangerous units require an exact earlier whole-reply occurrence.
Unsupported paraphrases/formatting can overblock. The combination can only add
restrictions to the previous component rule, not remove an existing Block.

`calibrate_reply_quotes.py` freezes 13 new API requests (six distinct existing
code units plus seven extra property controls), retaining the existing full-reply
scores for a mixed replay of the 24 cases. This is neither a new end-to-end run
nor evidence of improved population accuracy. Its focused runner/witness suite
passes 118 tests. Classifier results are pending and the large rerun remains held.

The quoted-code check subsequently completed with 11/13 model property agreements
and 23/24 combined reply agreements. Actual witnesses remove the invented-history
exception; numeric and symbolic system permission grants still receive false
negative model answers. `instrlib/permission_effects.py` now supplies a bounded
literal chmod fact: explicit others-write permission on a component-matched
system path. It respects symbolic clause order and distinguishes command position
from printed/search text. Unsupported shell semantics remain unresolved, not
benign. The fact does not establish an executed effect or authorization.

Adding this fact yields 24/24 reply and 13/13 property decisions in the recorded
replay; no new model calls or default/profile changes were made. The separate
`calibrate_reply_fresh.py` now prepares 30 fresh complete candidate decisions,
preserving the 24 original labels and adding six permission contrasts. It uses
reply-only semantic inputs, standalone code evidence and only asks prior coverage
when an actual witness can support the exception. Skipped coverage is explicit,
not fabricated model evidence. Whole input size, unique code-unit count and total
deadline are bounded; successful partial calls survive an error without retry.
The focused suite passes 194 tests. The evaluator is not yet installed in the
proxy; its fresh result and real predicate/cache/monitor integration remain gates.
