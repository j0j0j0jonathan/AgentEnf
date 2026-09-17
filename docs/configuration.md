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
