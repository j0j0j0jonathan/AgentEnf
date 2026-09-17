# Architecture

An API request or runtime hook creates a timepoint. Chat mapping or tool mapping produces lifecycle and classification events. The policy loader composes the configured MFOTL rules and signature. The process bridge sends the events to EnfGuard, then the proxy applies its verdict at the pending boundary.

| Component | Responsibility |
|---|---|
| `proxy.py` | HTTP routes, enforcement sequencing, provider forwarding, approvals and administrative operations |
| `runtime_state.py` | Process-local session state, call tracking, locks and pending approval records |
| `provider_streams.py` | Buffered SSE parsing and serialization for supported providers |
| `mappings.py` | Chat payloads to lifecycle events |
| `instrlib/tool_mapper.py` | Risk classification, classifier registration and event assembly |
| `instrlib/command_risk.py` | Shell and inline-code risk checks and benign-operation exceptions |
| `instrlib/shell_normalization.py` | Bounded textual shell normalization without execution |
| `instrlib/tool_identity.py` | Tool aliases and structural mechanism inference |
| `instrlib/path_confinement.py` | Host and virtual workspace path checks |
| `instrlib/tool_judge.py` | Optional routed semantic classification |
| `predicates.py`, `batch_judge.py` | Policy predicate execution, caching and pre-evaluation |
| `yaml_loader.py`, `enfguard.sig` | Configuration, formula composition and event vocabulary |
| `instrlib/enforcer.py` | Persistent EnfGuard subprocess protocol |
| `handlers.py` | Provider response normalization and verdict application |
| `frontend/`, `static/` | Enforcement console and chat client |

The public mapper entry points remain in `instrlib.tool_mapper`. Provider stream helpers and state types are re-exported by `proxy` for compatibility with integrations and tests.

## Adding a rule

Start with a policy preset. Reuse existing `Classify` dimensions where they answer your question. For a new question, add a fact producer and a corresponding vocabulary entry, then write a formula describing the required response. Add both a positive regression and a benign control. Heuristic checks are evidence producers and can misclassify content.

## State and concurrency

The proxy serializes access to its monitor history. Interactive approvals await an asynchronous event, allowing feedback requests to resolve them. Tool hooks must remain waiting until the HTTP response arrives.

The mapper accumulates proposed write fragments by session and normalized path. It bounds the number of paths and retained text. The accumulated text is an observation buffer, not a reconstructed filesystem. A rejected proposal or later overwrite does not make it a verified file snapshot.

Streaming responses are buffered for enforcement before release. This permits response checks but does not preserve the upstream provider's token-by-token delivery latency.
