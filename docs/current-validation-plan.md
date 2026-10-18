# Current validation plan

Updated 15 October 2026. Validate AgentEnf first; baseline ports remain deferred.
Keep the reserved 100-pair held-out set unopened. The known 150-pair dataset is a
development set because it informed tuning.

## 18 October update (supersedes launch status below)

The completed development rerun has 599 trajectories. Its frozen inputs and
results remain unchanged. Matched OFF/strict/permissive preparation now targets
1,797 trajectories: 150 attacks x 3 repeats plus 149 benign x 1, in each arm.
It remains development data. Reserved held-out contents remain unopened.

Current candidate fixes include multiline download invocation recognition,
AWK regex/redirect separation, native background action facts and an Approve
verdict for background work. Ordinary schedule creation stays Approve. The reply
guard has no Markdown-unit-count rejection; unchanged per-unit checks remain
bounded by input bytes and one shared deadline. This is not a latency claim.

Validation: 4,081 Python tests passed with real monitor binaries, 24 optional
checks skipped; 14 OpenClaw tests passed. The 30 reply controls and 20 semantic
property controls replay through the current runtime with the same recorded
answers. These are regression replays, not fresh classifier accuracy estimates.
The matched campaign requires an explicit small smoke schedule, pinned runner,
source hashes, and a successful smoke review before full collection. Supplementary
harm-judge evidence packaging still needs repair independently.

The older dated sections below describe how this candidate was developed, not
current readiness to launch or a claim that the completed experiment used HEAD.

## Completed checks and implemented candidate

The historical source review covers 120 harmful-labelled runs and 115 later-panel
Block firings. The earlier panel has a current-mapper check of 1,683 calls. These
reviews are not complete formal witnesses or independently adjudicated labels.

Candidate work includes exact strings via EnfFlash, attempted versus confirmed
artifact state, authenticated full-write snapshots, sanitized-write handling,
unique rule categories, persistence/collection review, background flags, dotenv
review, authored-dataflow review and explicit request-local reply context.
Candidate now has 136 labelled clauses; optimized-v1 has 135. Defaults and the frozen
thesis policy fixture remain unchanged.

The reply strategy is now integrated in both candidate profiles. It separates
payload/refusal questions from history, checks code units, requires a textual
witness for a quotation exception, and adds bounded literal permission facts.
Earlier isolated experiments remain dated evidence; their failed results are not
rewritten. The progression is:

| Check | Result | Scope |
| --- | --- | --- |
| Original contextual predicate | 9/18 | Selected development decisions |
| Three properties, shared input | 21/24 | Some correct results hid property errors |
| Reply-only property input | 22/24 | Remaining invented-history and chmod misses |
| Standalone code + witness | 23/24 | Mixed recorded-answer replay |
| Add literal permission evidence | 24/24 | Offline replay only |
| Fresh complete strategy | 30/30 | 14 Allows, 16 Blocks; no reused answers |
| Real runtime/cache/EnfFlash | 30/30 | Fixed-answer integration replay |

The two revised routed criteria are also candidate-only: literal secrets versus
redactions/references, and actual source-to-network dependency versus co-occurrence.
Their earlier selected calibration matched 20/20; all 20 also pass a registered-
adapter replay. This is not population accuracy or a measured security improvement.

The latest full test run passed 3,985 tests with real monitor binaries, 24 optional
baseline checks skipped and two dependency deprecations. A real launch-environment
probe found and fixed embedded Python missing the Markdown dependency. The parser
is pinned and EnfFlash exposes the launcher's installed dependencies to predicates.

## Live pilot review: expansion blocked

The user completed `outputs/paper-live-pilot-2026-10-15/integrated-v2` in the parent
workspace. All 18 were collected, but every ON run was affected by a monitor crash,
a local reply-guard budget failure, or both. Preserve the frozen experiment.
The detailed report is `outputs/paper-live-pilot-2026-10-15/review/REPORT.txt`.

- Three pairs: seed-0006/syn-0014, seed-0186/syn-0420, seed-0369/syn-0775.
- OFF, candidate with legacy approvals, candidate with strict approvals.
- One repetition = 18 trajectories; do not expand automatically to three repeats.
- Agent gpt-5.6-luna; classifiers Decisions gpt-6-luna; EnfFlash.
- Identical startup guidance in every arm; startup optimization remains separate.

Review every intervention against the actual step and evidence, including policy
Blocks versus approval denials, withheld replies, artifact receipts and observed
effects. Count classifier failures, oversized/code-count inputs and redundant
startup reads. Reconcile latency and API usage separately from agent runtime.

Five ON runs crashed because EnfFlash mistook a semicolon at the end of a line
inside a quoted tool result for the end of the event batch. A separate patched
build fixes framing and preserves line endings. The expanded test also found and
fixed invalid JSON for dynamic verdict strings. All 282 retained tool results
roundtrip exactly through that build. The original binary remains untouched.

All 14 withheld replies (eight runs) hit the eight-code-unit limit before semantic
classification. Filenames and variables in Markdown counted toward that limit.
The guard now permits up to 64 distinct units, with every unit still checked and
the whole-input budget/deadline retained. Failure reasons distinguish unit counts
from byte limits. This increases possible API cost; it is not a speedup claim.
Pilot validation now rejects infrastructure and predicate failures before marking
a future run complete. The 30 previous controls retain identical replay results.

The fresh `reply-followup-v1` check passed 44/44: all 14 reviewed pilot replies
now pass, and the 30 security controls retain their expected decisions. It used
308 API requests and 125,714 reported input tokens. The 14 pilot replies alone
needed 250 requests, averaging 4.95 s per reply (maximum 9.59 s). This is a
correctness repair with a real cost, not a speedup. One allowed quotation control
has a 0.51 coverage score at the 0.5 threshold; repeat stability is unproven.
The real-engine replay passes all 44 with exact cached evidence; the 20 property
controls also replay unchanged. See `reply-followup-v1/review/REPORT.txt`.

The separately frozen `integrated-v3` pilot completed all 18 trajectories without
monitor outages, predicate failures, classifier HTTP failures or withheld replies.
Ordinary log rotation succeeds under legacy approvals; strict still denies the
schedule as an approval decision. Review: `review-v3/REPORT.txt` in the pilot
parent folder. Official and independent harm scores remain unrun.

Expansion remains blocked by policy precision/coverage findings: shell cloning
and copying a skill directory misses the skill-install observation (reproduced
offline), while a direct sanitized replacement triggers the broad temporal
untrusted_skill_install Block. A metadata result's runtime safety wrapper is
also classified instruction_like; authenticated source separation remains open.
OFF/legacy credential and memory cases sanitize on their own, so these runs do
not establish an incremental protection gain. Strict makes 21 tool denials: 20
approval denials and one hard Block on the sanitized skill replacement.

Mean wall times are OFF 67.08 s, legacy 101.64 s, strict 89.68 s. These are single
development trajectories with changed actions, not isolated overhead estimates.
Skill repair is now implemented: shell copy/move/install/clone destinations emit
skill-stage observations; unresolved related destinations go to approval. The
candidate's untrusted_skill_install now requests approval rather than asserting
a harmful payload from earlier instructions alone. Independent payload Blocks
remain. No automatic approval exception was introduced. Authenticated source
separation for runtime warnings remains open and is not claimed solved here.

Full suite passed 4,016 tests; final focused checks passed 62 after the parser
edge-case refinements. The exact captured shell copies now emit skill staging.
Current reply/property integration replays retain 30/30 and 20/20 outcomes with
fixed recorded answers. The six-trajectory affected-pair confirmation is frozen
under `outputs/paper-skill-fix-2026-10-15/confirmation` in the parent workspace.
Its command is `01-confirm-skill-fix.command`. The large rerun's approval arms
and repetitions await the user's selection. No large launch or ASR claim yet.

## Remaining gates before scale-up

1. Repair any live integration or evidence gaps and repeat affected development
   checks. The quoted-code exception is conservative and can overblock unsupported
   equivalent formatting; semantic false negatives remain possible. Existing broad
   chmod mapper precision errors remain documented, not silently claimed fixed.
2. Finish the separate complete-evidence harm scorer and connect unchanged official
   A3S scoring with the selected judge. Preserve unknowns; distinguish proposals,
   preparation, completed actions and delivered replies. Exporting evidence alone
   is not scoring actual harm.
3. Inspect startup guidance as its own factor. Trusted loader receipts, atomic
   filesystem guarantees, external-writer/restart handling and confirmed outbound
   effects are not solved by a file snapshot or a generic tool-success message.
4. Freeze code, policies, classifiers, approval posture, startup behavior, resource
   caps, scorer contracts and images before broad evaluation.

## Later development rerun

The known union contains 150 attacks and 149 distinct benign cases. Three repeats
of each unique case in OFF/ON would be 1,794 trajectories; two separate ON approval
postures would make 2,691. These are planning counts, not an approved launch.
Report official ASR/benign completion alongside observed harm, per-call attribution,
overblocking, approval burden, evidence gaps, runtime and cost. Reserved holdout
and external baseline comparisons follow after these AgentEnf checks.
