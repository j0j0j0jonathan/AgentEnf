# Runtime HTTP contract

All tool requests carry `X-Admin-Token`. Use a stable `sid` for one agent session and a unique `call_id` for each tool invocation. Omit `tid` and let the proxy allocate it. Reuse the call identifier when reporting the result.

Before executing a tool, await `POST /v1/tool_execute`:

```json
{
  "sid": "session-1",
  "call_id": "call-1",
  "tool_name": "write_file",
  "tool_input": {"path": "/workspace/report.txt", "content": "Example"},
  "workspace_roots": ["/workspace"]
}
```

Only execute when the successful response explicitly contains `decision: "allow"`. Stop for `block`, malformed responses, connection failures or timeouts. The hook remains pending during an interactive approval. For audit mode, configure that choice explicitly at the proxy.

After execution, send `POST /v1/tool_result` with `sid`, `call_id`, `tool_name`, `tool_input`, `tool_response`, `exit_code` and `workspace_roots`. The returned verdict can inform later handling, but cannot undo the completed effect. The example adapters do not redact or suppress the result.

Chat endpoints are `/v1/chat/completions`, `/v1/responses` and `/v1/messages`. Point the client's base URL at the proxy, preserve provider authentication, and send `X-Session-ID` when the client permits custom headers. The tool and chat paths should use the same session identity if their observations need to join in policy.

`GET /health` checks the service. `GET /trace/{tid}` retrieves an authenticated trace. `GET /pending_approvals` lists pending decisions. Resolve one with `POST /feedback` and JSON containing `tid`, `kind` (`approve` or `deny`) and optional `payload`.
