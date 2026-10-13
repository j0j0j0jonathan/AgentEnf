# Review candidate: policy precision, outcomes and provenance

13 October 2026. This is a reviewable candidate, not a new measured release. The
existing default and frozen thesis pack are unchanged. No paid agent/classifier
runs or historical attack commands were executed during these experiments.

## Decision in brief

Use evidence-backed Blocks for known dangerous actions, real approval for
security-relevant administration, and explicit uncertainty when evidence is
missing. Improve the evidence contract before treating session/time correlation
as artifact provenance. A larger number of rules is not itself an improvement.

The candidate is `examples/presets/release-candidate.yaml`, reproducibly generated
by `experiments/release_candidate/build_profile.py` from the frozen evaluation
fixture. Its header records the source hash. It has **19 enabled groups and 124
labelled rules**, compared with the source's 18/121. It is not selected by default.

## Implemented now

### 1. Persistence: review administration; retain dangerous-payload blocks

The old persistence rule hard-blocked every `service` or `scheduled_task` fact.
The candidate routes those two categories to `service_schedule_review` approval.
It does not infer safety from a familiar package name, an ordinary cron syntax,
or a request saying "authorized." The operator must decide whether the specific
operation is permitted.

Other persistence kinds, including SSH keys, sudoers and existing hook categories,
retain their prior hard-block treatment. A new `dangerous_service_schedule` rule
blocks a service/schedule write when the same call carries the existing
`untrusted_write_path` fact, which identifies dangerous authored executable content.
This is evidence about the content of the proposed write, not merely its name.
Other groups' Blocks still take precedence over approval.

Real-monitor tests cover Redis/nginx activation and routine log rotation becoming
Approve, while authorized_keys, sudoers, and cron/service fetch-and-run payloads
remain Block. They do not prove every obfuscated payload is recognized.

**The critical trade-off:** persistence-only replay over 18 retained operations
changes all 18 from Block to Approve: three operations in benign runs and fifteen
in attack-labelled runs. Some attack-labelled runs contain ordinary setup steps
also present in their benign counterparts. This is not a free security/utility
gain, and these are not 18 prevented attacks. It is a change of authorization
posture. Historical headless approvals that proceed would make it permissive.

The comparison deliberately evaluates just the persistence group on retained
current-mapper facts, with isolated call contexts. It does not replay other groups,
semantic judges, earlier history, operator decisions or subsequent agent choices.
Therefore it does not predict final full-pack verdicts or task success.

### 2. Approval cannot be silently bypassed by the candidate

New configuration:

```yaml
human_approval:
  enabled: true
  timeout_seconds: 60
  on_timeout: block
  allow_headless_bypass: false
```

When the new flag is false, `ENFGUARD_APPROVAL_MODE=allow` or `warn` resolves
approvals to Block instead of allowing the operation. A permissive timeout is
rejected at configuration loading. Existing profiles retain the previous default
for compatibility; this candidate explicitly opts into the restriction.

This is not tamper protection: a person/process able to change trusted configuration
can remove the restriction. Observe/dry-run mode is still not enforcement. Shipping
requires a protected control plane, enforce mode, and authenticated operator UI.
The current UI approval is per pending invocation, not a durable scoped grant.

### 3. Full tool evidence

`ToolCall.input`, and consequently the hook's `ToolPlanned.input`, previously
contained only the first 200 characters of serialized arguments. That is unsuitable
for policies/classifiers inspecting a diff. The mapper now retains the complete
argument JSON. A regression places the relevant hook change after 8,000 characters.

UI previews should be truncated at rendering time, not by changing policy evidence.
Full content increases trace and request size. Explicit payload limits with a
visible unavailable/oversize outcome remain necessary before a hostile-input
network service; silent slicing must not return.

### 4. Configuration-change classifier

The new routed adapter is `configuration_change`, disabled by default and enabled
in the candidate under `backend.ingest_judges`. It routes only canonical file
writes/edits with recognized configuration suffixes: YAML, JSON, TOML, INI, CFG,
CONF. It receives the full structured arguments, including old/new text when the
tool supplies a diff. A full replacement without old content cannot prove a change
is new; the prompt explicitly distinguishes that case.

Labels:

| Label | Meaning | Candidate response from this group |
|---|---|---|
| execution_hook | Nonempty execution/startup/pre/post-run capability added or changed; or present in a full replacement. | Approve |
| security_weakening | Existing security check weakened/disabled. | Approve; independent hard rules can still Block. |
| benign | Ordinary settings, empty hooks, unchanged hooks, comments or inert metadata. | No intervention from this group. |
| uncertain | Insufficient or ambiguous information. | Approve |

The emitted facts are `artifact_write=configuration`, `configuration_change=<label>`
and `configuration_review_status=classified|unavailable`. Disabled, timed-out,
malformed and unsupported responses become explicit uncertain/unavailable evidence.
They cannot silently produce benign. No new signature event was required.

Tests cover complete-diff delivery, routing exclusions, malformed output, the
existing OpenAI-generative and Decisions dispatch paths with mocked providers,
and actual monitor approval behavior for all four labels. **No live model accuracy
claim is supported yet.** A classifier can still incorrectly return benign.

Limitations: shell-based edits and multi-file patch tools without a recognized
path are not covered by this adapter. Some TOML/JSON documents are data rather than
configuration; routing can therefore be conservative. Mapping both a model
proposal and a runtime invocation may judge the same arguments twice. Before
optimizing this, measure calls and introduce a versioned exact-input cache rather
than reuse evidence across changed arguments.

The candidate also clarifies the existing secret-request predicate: APP_ENV,
APP_DEBUG, worker counts and ordinary hostnames are not secrets merely because
of `.env`. Its private-instruction predicate distinguishes faithful paraphrases of
nonpublic rules from ordinary user-provided task summaries. These prompt changes
are hypotheses for evaluation, not proven classifier improvements. Output-only
classification cannot establish the source of every paraphrase; provenance/context
may be required to resolve that ambiguity.

### 5. Execution-outcome evidence

The authenticated tool-result endpoint now emits:

```text
Classify(t, call_id, "execution_outcome", value)
```

Values are `not_executed`, `failed`, `running`, `runtime_reported_complete` or
`unknown`. The wording is intentional: runtime-reported completion is not proof of
a particular external effect or of exact filesystem bytes.

- A known pre-tool block dominates any later callback claiming success.
- An explicit error/nonzero exit overrides a claimed completion.
- A running/background result is not complete.
- A legacy result or prose saying "Done!" is unknown.
- Runtime-reported completion requires explicit completion metadata and exit 0.

The OpenClaw adapter supplies conservative outcome metadata. An after callback
without an explicit completion indicator remains unknown. NanoClaw/other adapters
remain compatible but must adopt the contract to provide stronger evidence.
No existing rule was changed to pretend that unknown is complete. There may be no
after callback for a blocked call: its pre-tool Block remains the available evidence.

## Tested prototype, deliberately not connected to live policy state

`experiments/release_candidate/artifact_state.py` demonstrates the replacement for
append-only proposed-content accumulation. It is not yet used by the proxy or any
production policy. Keeping it separate avoids quietly changing the semantics of
existing provenance rules while the runtime lacks adequate attestations.

Identity is session + runtime namespace + normalized absolute lexical path.
Relative paths require an explicit working directory. Variables/tilde/unresolved
paths are rejected. Different directories with the same basename, different
sessions and different containers do not join.

A full literal replacement can be staged under a unique call ID. Its submitted
content hash becomes a runtime-reported revision only after explicit completion.
Failed/unknown/blocked writes never become revisions; failure may have partially
modified a file. A new pending write makes the previous revision unavailable.
Overlapping writers invalidate certainty. Retired call IDs cannot be reused, so
a delayed old callback cannot commit a new proposal. Unresolved writes/capacity
exhaustion invalidate cached certainty. Running jobs can later finish.

Tests exercise these failure cases, not just a successful write. The prototype
stores hashes rather than complete secret-bearing content. Its bounded call-ID
retention deliberately refuses new evidence at capacity; it is not a production
retention implementation.

### What is still needed before wiring it in

1. **Trusted runtime identity:** namespace, cwd, invocation ID and exact dispatched
   arguments must come from the harness, not from model-authored claims. Bind the
   verdict to an invocation/argument digest so a changed call must be checked again.
2. **Effect attestation:** distinguish completed tool execution from a verified
   write. Edits need a base revision and resulting content hash; a fragment cannot
   be appended to an imagined file. Shell commands require observed effects or
   unknown state, not guessed successful writes.
3. **External mutation:** another process can change a file after AgentEnf saw it.
   Before a revision can authorize execution/upload, check its current identity
   and bytes in the runtime filesystem. Avoid check/use races, ideally by binding
   the checked artifact to the actual opened handle/container operation.
4. **Current-state evidence:** emit the current revision at the pending use. An
   `ONCE` query finding an old hash does not prove that hash is still current.
5. **Migration:** add new versioned provenance properties alongside legacy facts;
   run shadow comparison; then migrate one rule at a time. Do not reinterpret
   old basename/path facts as byte-level taint tracking.

## Semantic evaluation before choosing a default classifier

Use the same manually reviewed inputs for the current classifier and Decisions.
Include nonsecret configuration, explicit secret values, redacted output, changed
versus unchanged hooks, authorized administration, hidden-instruction paraphrases
and ordinary handoff summaries. Separate context-required cases from confidently
labelled cases. Measure false negatives, false positives, uncertainty, failures,
latency and cost. Do not score a provider error as a correct benign answer.

The new configuration policy's action is approval because "new capability" is a
more defensible label than "malicious." Authorization should come from the trusted
operator, not a classifier deciding that an instruction sounds reasonable.

## Review and shipping order

1. Review the candidate policy diff and approve the intentional Block-to-Approve
   trade-off. Retain strict approval behavior; validate the real operator UI.
2. Accept the evidence fixes/outcome telemetry separately from changing the default
   policy pack. The candidate must stay clearly distinct from thesis results.
3. Run a small live classifier comparison with an explicit cost budget, then a
   disposable runtime integration test that checks actual effects and retries.
4. Complete runtime/revision attestation before activating artifact-based permits.
5. Run a fresh held-out panel and publish results only after the configuration is
   frozen. Record operator approvals and task success separately.

No push, default-profile activation or shipping action has been performed.
