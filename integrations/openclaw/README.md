# OpenClaw: connect both enforcement boundaries

Start with the repository [offline quickstart](../../docs/quickstart.md) and get
its Allow/Block check passing. This guide then connects an OpenClaw installation
to the same local service. AgentEnf does not install OpenClaw itself.

The profile below is isolated from your normal OpenClaw configuration. It routes
model traffic through the proxy **and** registers the pre-tool/post-tool plugin.
The retained plugin identifier is `enfguard-gate`; its name is AgentEnf Gate.

## 1. Prepare the isolated profile

In the AgentEnf checkout with `.venv` activated:

```bash
python scripts/prepare_openclaw.py --model YOUR_OPENAI_MODEL_ID
```

Replace `YOUR_OPENAI_MODEL_ID` with an OpenAI Responses model available to your
account, without an `openai/` prefix. This is the **agent model**, separate from the
policy classifier. The script reads the quickstart port and admin token and writes
`state/quickstart/openclaw/openclaw.json`. It refuses to overwrite an existing
profile. It stores no provider API key and never edits `~/.openclaw/openclaw.json`.

It creates this configuration structure (paths and local tokens are generated):

```json
{
  "agents": {"defaults": {
    "workspace": "/absolute/path/to/AgentEnf/state/quickstart/workspace",
    "model": {"primary": "openai/YOUR_OPENAI_MODEL_ID"}
  }},
  "models": {"providers": {"openai": {
    "baseUrl": "http://127.0.0.1:9000/v1",
    "apiKey": "${OPENAI_API_KEY}",
    "api": "openai-responses",
    "headers": {"x-session-id": "ONE_SHARED_SESSION_ID"},
    "models": [{"id": "YOUR_OPENAI_MODEL_ID", "name": "YOUR_OPENAI_MODEL_ID"}]
  }}},
  "gateway": {
    "mode": "local", "port": 18799, "bind": "loopback",
    "auth": {"mode": "token", "token": "GENERATED_GATEWAY_TOKEN"}
  },
  "plugins": {
    "allow": ["openai", "enfguard-gate"],
    "load": {"paths": ["/absolute/path/to/AgentEnf/integrations/openclaw/enfguard-gate"]},
    "entries": {"enfguard-gate": {"enabled": true, "config": {
      "enabled": true,
      "apiUrl": "http://127.0.0.1:9000",
      "adminToken": "SAME_ADMIN_TOKEN_AS_AGENTENF",
      "sid": "ONE_SHARED_SESSION_ID",
      "failMode": "block",
      "workspaceRoots": ["/absolute/path/to/AgentEnf/state/quickstart/workspace"]
    }}}
  }
}
```

## 2. Start the gateway in another terminal

Keep AgentEnf running in Terminal 1. From the repo root in Terminal 2:

```bash
export OPENCLAW_STATE_DIR="$PWD/state/quickstart/openclaw"
export OPENCLAW_CONFIG_PATH="$OPENCLAW_STATE_DIR/openclaw.json"
```

Supply `OPENAI_API_KEY` in this terminal through your secret manager or a hidden
prompt, then `export OPENAI_API_KEY`. Bash: `read -r -s -p 'OpenAI API key: ' OPENAI_API_KEY`.
Zsh: `read -r -s 'OPENAI_API_KEY?OpenAI API key: '`. Agent model calls incur provider
costs even while AgentEnf's quickstart classifier is disabled.

```bash
openclaw config validate
openclaw gateway
```

Leave the gateway running. In Terminal 3, repeat the two profile exports and the
provider-key setup, then open its UI:

```bash
openclaw dashboard
```

Use `python scripts/quickstart.py console` to open AgentEnf's separate console.
Do not use bare OpenClaw commands without the profile variables; they target your
normal configuration instead. Three credentials have distinct roles: the provider
API key, the AgentEnf admin token, and the OpenClaw gateway token.

## 3. Verify an actual agent turn

Start one new conversation. Ask it to read `README.md`. Then ask it to read
`config/secrets.env`, which contains only invented quickstart data. With the
offline quickstart policy, a recognised credential-file access should be blocked.
Inspect `ToolPlanned`, the classification and `quickstart_credential_read` in the
trace. If the model declines without a tool call, that is model refusal, not proof
that the hook blocked execution. The deterministic HTTP quickstart remains a
separate wiring test.

For the temporal audit example, stop AgentEnf and use the
[Decisions direct-launch configuration](../../docs/configuration.md#direct-launch-after-the-quickstart),
keeping the same port, token and workspace. That rule blocks a credential read
following a request for exact secret values; it does not block every credential
read. Check that model-request and tool-call `Turn` events share a nonempty session.

**Session scope matters:** the generated profile fixes one shared ID in the model
provider header and tool hook. This is for a single controlled conversation.
Starting another chat does not reset that ID. For multiple users or sessions, the
integration must propagate each runtime session dynamically to model traffic and
tool hooks. The plugin alone cannot add a per-session model header. Do not reuse
this fixed identity across unrelated chats.

Stop the gateway and proxy with Ctrl+C in their own terminals. For a fresh isolated
run, choose a new `--state-dir` for both quickstart and profile preparation and
point the profile exports at it. Existing histories are preserved.

## Existing installations and containers

To install into an existing OpenClaw profile instead of the isolated load path:

```bash
openclaw plugins install /absolute/path/to/AgentEnf/integrations/openclaw/enfguard-gate
```

Merge `plugins.entries.enfguard-gate.config` and provider settings into that
profile; preserve unrelated entries and add the plugin to any existing allowlist.
Restart/reload the gateway after changing the plugin. Verify actual runtime calls,
not just installation output. The isolated example was validated with OpenClaw
2026.6.10; other versions may have different plugin activation requirements.
Consult [upstream plugin configuration](https://docs.openclaw.ai/tools/plugin)
and [configuration reference](https://docs.openclaw.ai/gateway/configuration-reference).

Localhost works only when proxy and runtime share a host/network namespace. For
Docker on macOS/Windows, a container commonly reaches the host using
`host.docker.internal`; Linux may require explicit host mapping. The proxy must
also listen on an address reachable from that container: the loopback-only
quickstart is intentionally host-local. Exposing it beyond loopback requires an
appropriate network/access-control setup. Set the provider URL and plugin URL to
the reachable proxy address and describe the agent's actual workspace view.

## Hook behaviour and denial messages

The plugin awaits `/v1/tool_execute` before execution. Missing, malformed, failed
or timed-out responses block by default. It lets the proxy allocate `tid`, and
uses runtime call/session identifiers where supplied. Fallback call IDs cannot
guarantee the same proposal/result join as stable runtime IDs.

`after_tool_call` reports results to `/v1/tool_result`; it cannot undo execution or
suppress result content. For interactive approvals, use the AgentEnf console and
allow time for approval plus classification within the hook's 120-second timeout.
`blockApprovals` can stop advisory/headless approval requests. Optional
`verdictsPath` records JSON lines; its parent directory must already exist.

Denials contain AgentEnf attribution, available rule IDs and a structured
`[EnfAgent enforcement]` JSON record (the marker preserves demo UI compatibility).
The record distinguishes policy blocks, denied approvals and service failures.
The plugin does not install a custom OpenClaw dashboard; a UI may render this record
as a separate notice. Confirm allowed, blocked and approval paths on your version
before relying on a deployment.
