# OpenAI Decisions classifier backend

AgentEnf supports `openai_decisions` alongside its existing text-generation
judge backends. This promotes the post-evaluation Decisions experiment into a
normal configurable backend; no monkey-patching or experiment directory is
required. The deterministic mapper, event signature, formulas and enforcement
engine do not change.

## Configuration

For policy predicates, select the backend in your YAML:

```yaml
backend:
  judge_backend: openai_decisions
  judge_decisions_model: gpt-6-luna
  judge_timeout_ms: 20000
```

Per-predicate `backend`, `model` and `timeout_ms` overrides still take precedence.
If a predicate explicitly selects the old backend, update that override too.
`kind: llm_judge` and `system_prompt` remain unchanged: the prompt supplies the
classification criterion. See `examples/decisions.yaml` for a complete single-rule
credential-read configuration, including fail-closed behaviour.

Routed classifiers are configured independently:

```sh
export ENFGUARD_TOOL_JUDGE_BACKEND=openai_decisions
export ENFGUARD_TOOL_JUDGE_MODEL=gpt-6-luna
```

Existing per-adapter `ENFGUARD_TOOL_JUDGE_MODEL_<ADAPTER>` overrides still win;
remove or update old model overrides when switching. Existing YAML ingest-judge
enablement and routing conditions are unchanged. The example disables routed
judges because its one policy only needs the semantic predicate.

Provide `OPENAI_API_KEY` through your environment. Separate predicate and routed
keys remain supported via `JUDGE_OPENAI_API_KEY` and
`ENFGUARD_TOOL_JUDGE_OPENAI_API_KEY`. Never put keys in policy files.
The endpoint defaults to `https://api.openai.com/v1/decisions`. An explicit
`ENFGUARD_DECISIONS_BASE_URL` overrides it. It intentionally does not inherit
`OPENAI_BASE_URL`, which may route the agent's model traffic through AgentEnf.
Restart the service after changing backend environment variables.

## What changes

- Policy predicates receive a probability, passed unchanged to the existing
  formula threshold (for example `> 0.5`).
- Single-label routed classifiers use fixed choice vocabularies. Broad content
  classification asks independent predicate questions and retains labels with
  probability above 0.5.
- Questions sharing an input can be batched. Different inputs are sent separately.
- There is no generated rationale. The trace records an explicit explanation of
  this limitation and includes the typed API response, returned model and usage
  inside the mapped reply's `decisions` field.
- API refusals, missing keys, invalid answers and HTTP errors propagate to the
  existing caller failure policy. Predicate `on_fail` still applies; routed
  classifier failures remain fail-open. There is no fallback to generation.
- Predicate cache keys include backend and model, separating Decisions results
  from legacy judge results. The transport reuses connections.

## Migration and evaluation

Use this backend for new runs through an explicit deployment configuration.
Do not rewrite old benchmark YAML files or describe old thesis results as
Decisions results. The existing default and evaluation configurations remain
unchanged. Compare attacks, benign tasks, verdicts, failures, wall time and API
usage before promoting a new deployment configuration. Probability estimates
and choice confidence are not guaranteed accuracy; thresholds need validation.
Offline tests validate the wire contract and integration, not model quality or
latency. No paid API call is required by the test suite.

The implementation follows the [official Decisions guide](https://developers.openai.com/api/docs/guides/decisions),
checked on 13 October 2026. That guide currently lists `gpt-6-luna` for this API.
