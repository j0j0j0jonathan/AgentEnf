/** AgentEnf pre-tool and post-tool callbacks for the Claude Agent SDK. */
export function createAgentEnfHooks({
  apiUrl,
  adminToken,
  sessionId,
  workspaceRoots = [],
  timeoutMs = 120_000,
  fetchImpl = globalThis.fetch,
  onObservationError = console.error,
}) {
  if (!apiUrl || !adminToken || !sessionId) {
    throw new Error("AgentEnf requires apiUrl, adminToken and sessionId");
  }
  const origin = apiUrl.replace(/\/+$/, "");
  async function post(route, input) {
    const response = await fetchImpl(`${origin}${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": adminToken },
      body: JSON.stringify({
        sid: sessionId,
        call_id: input.tool_use_id,
        tool_name: input.tool_name,
        tool_input: input.tool_input,
        workspace_roots: workspaceRoots,
        ...(route.endsWith("tool_result") ? {
          tool_response: typeof input.tool_response === "string"
            ? input.tool_response : JSON.stringify(input.tool_response ?? ""),
          exit_code: input.error ? 1 : 0,
        } : {}),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error(`AgentEnf returned HTTP ${response.status}`);
    return response.json();
  }
  const deny = (reason) => ({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  });
  return {
    preToolUse: async (input) => {
      if (!input.tool_use_id || !input.tool_name) return deny("Missing tool identity");
      try {
        const verdict = await post("/v1/tool_execute", input);
        if (verdict.decision === "block") return deny(verdict.reason || "Blocked by AgentEnf");
        if (verdict.decision !== "allow") return deny("Invalid AgentEnf decision");
        // Do not override the runtime's other permission checks with an explicit allow.
        return { continue: true };
      } catch (error) {
        return deny(`AgentEnf unavailable: ${error.message}`);
      }
    },
    postToolUse: async (input) => {
      try {
        await post("/v1/tool_result", input);
      } catch (error) {
        onObservationError(`AgentEnf result observation failed: ${error.message}`);
      }
      // The operation has completed. This callback does not suppress its result.
      return { continue: true };
    },
  };
}
