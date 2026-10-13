# AgentEnf

Programmable temporal runtime enforcement for LLM agents, developed for the ETH Zürich bachelor's thesis **Runtime Enforcement of Temporal Safety Policies for LLM Agents: Programmable Neuro-Symbolic Enforcement at LLM-Agent Effect Boundaries** by Jonathan Hofer.

AgentEnf intercepts chat traffic and planned tool actions, converts them into structured events, and evaluates user-authored policies with the [EnfGuard monitor](https://github.com/runtime-enforcement/whyenf). Policies can combine earlier observations with code-based or model-based classifications, then block, warn, or request approval.

Supported interfaces include OpenAI-compatible chat, OpenAI Responses, Anthropic Messages, and pre-tool and post-tool HTTP hooks. Integration examples are provided for OpenClaw and NanoClaw. The React console shows policies, traces, and pending approvals.

## Start here: see an Allow and a Block

You need **Python 3.12+, Node.js 22.12+ and a separately built EnfGuard monitor**.
Start with the [step-by-step quickstart](docs/quickstart.md). It makes no model
calls, needs no API key, and submits two tool proposals without executing them.

After [installing the monitor](docs/monitor.md):

```bash
git clone https://github.com/j0j0j0jonathan/AgentEnf.git
cd AgentEnf
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
npm --prefix frontend ci
npm --prefix frontend run build
python scripts/quickstart.py init --monitor "/absolute/path/to/whyenf/_build/default/bin/enfguard.exe"
python scripts/quickstart.py start
```

In a second terminal, enter the same checkout and activate `.venv`, then run:

```bash
source .venv/bin/activate
python scripts/quickstart.py check
python scripts/quickstart.py console
```

You should see **ALLOW** for a proposed README read and **BLOCK** for a proposed
credential-file read. The helper shares a saved local admin token between
terminals and opens the authenticated dashboard. See the guide for troubleshooting
and shutdown. This checks enforcement wiring; an agent still needs a runtime hook
to stop a real operation.

## Choose a configuration

| What you want | Where to start |
|---|---|
| Offline installation check | [Quickstart](docs/quickstart.md) |
| One temporal rule with typed model evidence | [Decisions example](examples/decisions.yaml) and [backend guide](docs/decisions.md) |
| Broader deployment pack | [Default preset](examples/presets/agentic-security.yaml): 15 enabled groups, 79 labelled rules |
| Exact thesis evaluation pack | [Evaluation fixture](tests/fixtures/policies/eval_combined_graduated_a3s.yaml): 18 enabled groups, 121 labelled rules |
| Direct launch, credentials and approvals | [Configuration](docs/configuration.md) |

The two packs are different configurations. The default preset is not the exact
pack used for the reported evaluation. Model-based configurations require provider
credentials and can incur API costs. Existing backends remain available.

## Integrate an agent

- [OpenClaw plugin](integrations/openclaw/README.md)
- [NanoClaw and Claude Agent SDK hooks](integrations/nanoclaw/README.md)
- [HTTP contract for another runtime](docs/integration.md)

## Develop

```bash
python -m pytest
python -m ruff check
npm --prefix frontend run build
node --test integrations/nanoclaw/*.test.mjs integrations/openclaw/*.test.mjs frontend/src/traceUtils.test.mjs
```

Most Python tests use stubs. Tests requiring the actual monitor skip unless `ENFGUARD_BIN` is explicitly set. Set it to a compatible executable to include them. Tests classify attack-shaped strings without executing those commands.

[Architecture](docs/architecture.md) explains module ownership and extension points. [Evaluation](docs/evaluation.md) links the external A3S/ASEval project and describes its use with AgentEnf. The repository ships runtime source, regression tests, and a [1,269-prompt development corpus](datasets/development-prompts/README.md). Research notes, private traces, external benchmark datasets, and historical result bundles are excluded.

## Deployment scope

Use one service worker per state directory. Monitor history, pending approvals, and mapper buffers are process-local. Protect access to the service and its trusted policy configuration. Trace files can contain prompts, tool arguments, and model responses.

A pre-tool hook can withhold a pending action. A post-tool hook records an operation that already happened. The OpenClaw and NanoClaw examples do not suppress tool-result content. Path checks use the proxy's filesystem view or declared virtual roots, and do not establish complete information-flow tracking through arbitrary copies or external execution.

## Attribution and license

AgentEnf builds on EnfGuard and the InstrLib instrumentation work. See [third-party notices](THIRD_PARTY_NOTICES.md) for source provenance and component licenses. AgentEnf is distributed under GPL-3.0. The separately installed monitor and other dependencies retain their respective licenses.

## Typed classifier backend

OpenAI Decisions is available as `openai_decisions` for policy predicates and routed tool classifiers. See [configuration and migration](docs/decisions.md) and the [credential-read example](examples/decisions.yaml). Existing backends and evaluation fixtures retain their original settings.
