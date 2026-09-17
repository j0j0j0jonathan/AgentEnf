# NanoClaw / Claude Agent SDK

NanoClaw's Claude provider runs through the Anthropic Claude Agent SDK. This adapter supplies awaited `PreToolUse` and observational `PostToolUse` callbacks. The thesis integration originally used `canUseTool`. A pre-tool hook also covers calls that a permission allowlist would otherwise automatically approve.

Copy `hooks.mjs` beside your NanoClaw agent-runner source and import it where the Claude SDK query is configured. Current NanoClaw keeps that configuration in `container/agent-runner/src/providers/claude.ts`. Preserve its existing callbacks and add these to their corresponding hook lists:

```js
import { createAgentEnfHooks } from './hooks.mjs'; // adjust to copied location

const enforcement = createAgentEnfHooks({
  apiUrl: process.env.ENFGUARD_API_URL,
  adminToken: process.env.ENFGUARD_ADMIN_TOKEN,
  sessionId: agentSessionId, // stable host-provided identifier
  workspaceRoots: ['/workspace/group'],
});

const hooks = {
  ...existingHooks,
  PreToolUse: [
    ...(existingHooks.PreToolUse ?? []),
    { hooks: [enforcement.preToolUse] },
  ],
  PostToolUse: [
    ...(existingHooks.PostToolUse ?? []),
    { hooks: [enforcement.postToolUse] },
  ],
};
// Pass hooks to the SDK query options and rebuild the agent-runner container.
```

This is an integration module, not a replacement NanoClaw checkout. Use the runtime's actual session identifier, not the literal variable name in the example. Preserve other permission checks. The pre-hook returns a denial for blocked, malformed, failed or timed-out gate requests, and otherwise lets the runtime continue its own permission handling.

The container must reach the proxy URL. Supply the token only to the trusted integration process. For a deployment that keeps credentials outside the container, have NanoClaw's host credential proxy forward these two routes and inject the token there. Never include the admin token in model prompts or tool-visible files.

The post-hook records the completed tool result. It does not undo the operation or hide result content. Hook timeouts must exceed the configured interactive approval timeout plus enforcement overhead.

Upstream source: [NanoClaw Claude provider](https://github.com/nanocoai/nanoclaw/blob/main/container/agent-runner/src/providers/claude.ts). The adapter is tested locally against the HTTP contract. Recheck the hook wiring when upgrading NanoClaw or the SDK.
