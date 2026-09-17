# OpenClaw

`enfguard-gate/` is a native OpenClaw plugin with its own manifest and entry module. Its retained plugin identifier is `enfguard-gate`. The user-facing name is AgentEnf Gate.

Install the local plugin with OpenClaw's plugin installer:

```bash
openclaw plugins install /absolute/path/to/AgentEnf/integrations/openclaw/enfguard-gate
```

Configure the `enfguard-gate` entry in your OpenClaw configuration. Supply the same admin token as the proxy, preferably through `ENFGUARD_ADMIN_TOKEN` in the trusted runtime environment:

```json
{
  "enabled": true,
  "apiUrl": "http://host.docker.internal:9000",
  "failMode": "block",
  "workspaceRoots": ["/workspace"]
}
```

Use `http://127.0.0.1:9000` when the proxy and runtime share a host. Container networking differs on Linux. Configure a reachable address and host mapping as needed. Workspace roots must describe the agent's actual filesystem view.

The plugin awaits `/v1/tool_execute` before execution. Missing, malformed, failed or timed-out responses block by default. It omits `tid` so the proxy allocates a unique enforcement timepoint. It uses runtime call and session identifiers when available. A runtime that omits a call identifier cannot provide a reliable proposal-to-result join for that call.

The `after_tool_call` hook reports model-visible result content to `/v1/tool_result`. It is observational and does not suppress result content. Allowed proposals are not logged as completed effects. An optional `verdictsPath` records local JSON lines in addition to the proxy's audit trail. Ensure its parent directory exists and is writable.

`sid` can explicitly override session identity for a controlled single-session run. Avoid one fixed identity across unrelated sessions. `blockApprovals` can require headless approval requests to stop. For interactive approvals, use the proxy console and keep its timeout shorter than the plugin's 120-second request timeout.

The plugin's contract tests use a simulated OpenClaw hook registration. Before a live deployment, verify one allowed call, one blocked call and one approval with your installed OpenClaw version. Upstream [plugin installation](https://docs.openclaw.ai/tools/plugin) and [manifest documentation](https://docs.openclaw.ai/plugins/manifest) describe host configuration.
