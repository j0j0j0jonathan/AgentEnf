# Configuration

YAML policy files configure predicates, MFOTL formulas, classifiers, switches and approvals. `examples/presets/agentic-security.yaml` contains the composed security pack. Smaller presets demonstrate individual use cases. Configuration can load Python code and must come from a trusted deployer.

| Setting | Purpose |
|---|---|
| `ENFGUARD_YAML` | Policy file, default `enfguard.yaml` |
| `ENFGUARD_BIN` | Compatible monitor executable |
| `ENFGUARD_ADMIN_TOKEN` | Required token for tool, feedback and administrative endpoints |
| `ENFGUARD_TIME_MODE` | `wall_seconds` for native metric windows, or legacy `logical` |
| `ENFGUARD_WS_HOST_ROOTS` | Comma-separated host workspace roots |
| `ENFGUARD_WS_PREFIX_MAP` | Container-to-host mappings as `virtual=host` pairs |
| `ENFGUARD_WS_VIRTUAL_ROOTS` | Container-visible roots when host resolution is unavailable |
| `ENFGUARD_TOOL_JUDGE` | `0` disables ingest classifiers, `1` permits configured classifiers |
| `ENFGUARD_TOOL_JUDGE_MODEL` | Ingest classifier model identifier |
| `ENFGUARD_STATE_DIR`, `ENFGUARD_LOG_DIR` | Mutable files, excluded from Git |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | Provider credentials |
| `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL` | Upstream API origin |
| `ENFGUARD_CORS_ALLOW_ORIGINS` | Explicit browser origins, loopback by default |

Disabling ingest classifiers does not disable `llm_judge` predicates explicitly configured in a policy. Select a policy with no model predicates for a completely offline check.

`human_approval` configures whether approval is interactive, its timeout, and the timeout decision. `ENFGUARD_APPROVAL_MODE=interactive` is the normal setting. Headless `block`, `allow`, and `warn` are explicit alternatives. `warn` permits the action with an advisory, so an approval request is not evidence of prevention in that mode.

The `/pending_approvals` and `/feedback` API supports a separate approval UI. The console supplied with AgentEnf uses it. Set hook timeouts longer than the approval timeout plus classification and monitor overhead.

The default host workspace is the process's working directory. Configure the actual agent workspace before deployment. Declared virtual roots provide lexical checks but cannot reveal symlinks that exist only in another container.

## Direct launch after the quickstart

The quickstart helper always chooses its offline YAML. To run another policy,
stop that server, activate the venv and configure a direct launch from the repo root:

```bash
export ENFGUARD_ADMIN_TOKEN="$(cat state/quickstart/admin-token)"
export ENFGUARD_BIN=/absolute/path/to/whyenf/_build/default/bin/enfguard.exe
export ENFGUARD_TIME_MODE=wall_seconds
export ENFGUARD_YAML=examples/decisions.yaml
export ENFGUARD_WS_HOST_ROOTS="$PWD/state/quickstart/workspace"
export ENFGUARD_STATE_DIR="$PWD/state/decisions"
export ENFGUARD_LOG_DIR="$PWD/logs/decisions"
export ENFGUARD_APPROVAL_MODE=interactive
```

For example, in Bash, `read -r -s -p 'OpenAI API key: ' OPENAI_API_KEY` followed by
`export OPENAI_API_KEY` supplies the key without putting its value in shell history.
In Zsh, use `read -r -s 'OPENAI_API_KEY?OpenAI API key: '` then `export OPENAI_API_KEY`.
Now start the server:

```bash
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000 --workers 1
```

Open the console using `python scripts/quickstart.py console` in another terminal
(the default port is 9000 and you deliberately reused its token). The quickstart
`check` command is only for its own offline policy, not this semantic policy.

The API key authenticates provider model calls. The admin token authenticates
local tool, console and feedback requests. They are different secrets. Exported
variables belong to one terminal and its child processes; repeat exports in each
terminal that starts a service. `.env.example` is a reference, not automatically
loaded. To source a trusted local `.env` yourself, use `set -a; source .env; set +a`.

For the broader preset, change `ENFGUARD_YAML` to
`examples/presets/agentic-security.yaml`. It has 15 enabled groups / 79 labelled
rules; the thesis evaluation fixture has 18 / 121. Its historical classifier
settings include a short timeout and fail-open configuration: review them before
using it as your deployment policy. See [Decisions migration](decisions.md) for
selecting both semantic entry points; changing only the predicate backend does
not change routed classifiers.
