# AgentEnf

Programmable temporal runtime enforcement for LLM agents, developed for the ETH Zürich bachelor's thesis **Runtime Enforcement of Temporal Safety Policies for LLM Agents: Programmable Neuro-Symbolic Enforcement at LLM-Agent Effect Boundaries** by Jonathan Hofer.

AgentEnf intercepts chat traffic and planned tool actions, converts them into structured events, and evaluates user-authored policies with the [EnfGuard monitor](https://github.com/runtime-enforcement/whyenf). Policies can combine earlier observations with code-based or model-based classifications, then block, warn, or request approval.

Supported interfaces include OpenAI-compatible chat, OpenAI Responses, Anthropic Messages, and pre-tool and post-tool HTTP hooks. Integration examples are provided for OpenClaw and NanoClaw. The React console shows policies, traces, and pending approvals.

## Run from source

Requirements: Python 3.12+, Node.js 22.12+ for the console, and a compatible EnfGuard executable. Install the monitor using [the monitor setup instructions](docs/monitor.md) first. AgentEnf does not bundle its binary.

```bash
git clone https://github.com/j0j0j0jonathan/AgentEnf.git
cd AgentEnf
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
npm --prefix frontend ci
npm --prefix frontend run build

export ENFGUARD_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENFGUARD_BIN=/absolute/path/to/whyenf/_build/default/bin/enfguard.exe
export ENFGUARD_TIME_MODE=wall_seconds
export ENFGUARD_YAML=examples/presets/agentic-security.yaml
export ENFGUARD_WS_HOST_ROOTS=/absolute/path/to/agent/workspace
export OPENAI_API_KEY=your-provider-key
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000 --workers 1
```

Open `http://127.0.0.1:9000/enforcement` or `/chat`. Open the console once with `?admin_token=YOUR_TOKEN` to store its admin token locally in the browser. Keep the token in your local environment. `.env.example` lists common settings, but the application does not automatically load that file.

The security pack enables semantic checks and may call a model. See [configuration](docs/configuration.md) for model selection, disabling ingest classifiers, and approval behaviour. For a tool-only check without model calls, use `examples/nanoclaw/enfguard.nanoclaw-tools.yaml` and `ENFGUARD_TOOL_JUDGE=0`.

A tool gate checks an operation. It does not execute it:

```bash
curl http://127.0.0.1:9000/v1/tool_execute \
  -H 'Content-Type: application/json' \
  -H "X-Admin-Token: $ENFGUARD_ADMIN_TOKEN" \
  -d '{"sid":"demo","call_id":"demo-1","tool_name":"bash","tool_input":{"command":"echo hello"},"workspace_roots":["/workspace"]}'
```

The response contains `decision: "allow"` or `"block"`. A runtime must await this response before running the operation. An interactive approval keeps the request pending until feedback or the configured timeout.

## Integrate an agent

- [OpenClaw plugin](integrations/openclaw/README.md)
- [NanoClaw and Claude Agent SDK hooks](integrations/nanoclaw/README.md)
- [HTTP contract for another runtime](docs/integration.md)

## Develop

```bash
python -m pytest
python -m ruff check
npm --prefix frontend run build
node --test integrations/nanoclaw/*.test.mjs integrations/openclaw/*.test.mjs
```

Most Python tests use stubs. Tests requiring the actual monitor skip unless `ENFGUARD_BIN` is explicitly set. Set it to a compatible executable to include them. Tests classify attack-shaped strings without executing those commands.

[Architecture](docs/architecture.md) explains module ownership and extension points. [Evaluation](docs/evaluation.md) links the external A3S/ASEval project and describes its use with AgentEnf. The repository ships runtime source and regression tests. Research notes, private traces, benchmark datasets, and historical result bundles are excluded.

## Deployment scope

Use one service worker per state directory. Monitor history, pending approvals, and mapper buffers are process-local. Protect access to the service and its trusted policy configuration. Trace files can contain prompts, tool arguments, and model responses.

A pre-tool hook can withhold a pending action. A post-tool hook records an operation that already happened. The OpenClaw and NanoClaw examples do not suppress tool-result content. Path checks use the proxy's filesystem view or declared virtual roots, and do not establish complete information-flow tracking through arbitrary copies or external execution.

## Attribution and license

AgentEnf builds on EnfGuard and the InstrLib instrumentation work. See [third-party notices](THIRD_PARTY_NOTICES.md) for source provenance and component licenses. AgentEnf is distributed under GPL-3.0. The separately installed monitor and other dependencies retain their respective licenses.
