# Release readiness and the October 2026 hardening changes

AgentEnf is a research/developer enforcement system. A policy verdict only protects an operation when a trusted runtime submits that operation and honors the decision. The broader policy preset is not a security guarantee for unrestricted computer access.

## Changes in this patch

- Denial echoes and warning advisories are scoped by session as well as call ID.
- Call IDs remain opaque, case-sensitive identifiers. Adapters must explicitly map aliases rather than rely on punctuation removal.
- Predicates and routed judges receive the complete extracted input instead of a silently truncated prefix. Decisions batching groups by full input. Tool-result events preserve full text and line breaks.
- The judge cache identity includes the input/output contract version. Old cached answers and manual overrides must be reconsidered after a contract change.
- Pre-evaluated predicate answers are reused only for exactly matching content. The previous single-result fallback could substitute evidence about a different message in a temporal rule.
- Impact classification no longer confuses a subsequent system executable with a deletion target, and masks literal search patterns. Script filename suffixes no longer count as interpreter invocations.
- The OpenClaw plugin rejects unknown failure modes and preserves non-execution when an after callback follows a denied call.
- Event serialization preserves numeric-looking strings as strings and rejects nonfinite numeric values. Event equality no longer depends on hash equality.

The frozen evaluation policy fixture is unchanged. These are implementation fixes, not a new benchmark result or a new default policy pack.

- Response batches now repeat the original request Turn. Request and response are different monitor positions, so temporal output policies need the session identity alongside Completion. Standalone output checks were unaffected.

## Upgrade checks

1. Propagate the same canonical session ID through model traffic and tool hooks. Validate concurrent sessions with reused call IDs. A fixed ID is suitable for a controlled single-session demo, not a multi-user service.
2. If a harness/provider rewrites tool IDs, introduce an explicit mapping. Do not normalize unrelated IDs into the same identifier.
3. Expect changed classifier cache keys. Re-review any operator overrides; old answers used a different evidence contract.
4. Expect larger classifier requests and traces. Configure service access and retention accordingly. Input-size limits should produce explicit unavailable/partial evidence, not silently drop the end of the request.
5. Validate Unicode predicate arguments with the exact EnfGuard build. Removing the unsafe content fallback does not repair a monitor bridge that corrupts text.
6. Review any custom policy that relied on flattened whitespace in ToolResult text.

## Required deployment boundary

Keep the policy configuration, monitor, proxy, hook code and control-plane credentials outside the agent's writable/readable authority as appropriate. An agent with unrestricted shell access under the same OS identity may be able to disable its own enforcement. Loopback networking does not solve this. Use OS/container isolation and separate credentials.

Use one service worker per state directory. The current state/monitor design is not a multi-worker shared service. Do not expose the service as a multi-tenant endpoint without separate authorization for model ingress, gate submission, operator approvals and administration.

Use interactive approvals with an authenticated operator, or explicitly configure unresolved approvals to block. Unattended permissive approval behavior is not attack prevention.

Post-tool reporting observes an effect that may already have happened. The supplied OpenClaw/NanoClaw integrations do not guarantee tool-result suppression. Model-output enforcement and pre-tool enforcement have different protection points.

## Important remaining limitations

- **Proposal versus effect:** a planned or blocked write is not proof of filesystem contents. Authored-content accumulation should become versioned, outcome-aware artifact state.
- **Provenance:** some deferred-hook correlations use basenames. Session/time correlations do not prove that the same bytes or artifact caused a later action.
- **Message time:** seeing the last user message again in a model request is not a new user instruction. Stable message identity and original observation time are needed for precise expiry windows.
- **Shell syntax:** regex recognition still has code-versus-data ambiguities, especially compound commands, heredocs and dynamic construction. The targeted parsing fixes are not a complete shell interpreter.
- **Filesystem scope:** the proxy's filesystem view can differ from the agent's. Declared virtual roots cannot prove symlink confinement or prevent races in another filesystem.
- **Semantic failures:** routed classifiers can fail open; deployments need explicit handling for unavailable, timed-out or oversized evidence. Missing evidence must not be represented as confident benign evidence.
- **Policy scope:** requested services, schedulers, redacted support archives and skill installations can resemble persistence or exfiltration. Prefer scoped approval and artifact-specific evidence over blanket exclusions or blanket blocks.
- **Performance:** synchronous classifier work, repeated evidence-file scans and growing session state need bounded concurrency, indexing and retention. Measure queue/monitor/model time separately from end-to-end task duration.

## What to validate next

Use fresh held-out tasks after development on the retained A3S panels. Record the actual protected effect, verdict correctness, benign completion, approval burden, latency and cost separately. Compare deterministic-only, hybrid and full-pack configurations under matched conditions. A fired rule is not automatically a prevented attack, and a benign task label does not mean every operation must be permitted.

Prioritize generic regression pairs: safe and unsafe variants differing in command position, quoting, file identity, authorization, execution outcome or sensitive content. Include missing-session IDs, repeated call IDs, retries, classifier/monitor outages, cancellation and concurrent requests. Check effects through a trusted test runtime rather than only inspecting a Block log.

## Review candidate

See [the candidate design and experiments](release-candidate-design.md) for the opt-in persistence/configuration policy profile, conservative execution-outcome evidence and the separate artifact-revision prototype. These are not a newly evaluated default pack.
