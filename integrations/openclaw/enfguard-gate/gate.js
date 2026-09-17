import fs from "fs";

const DEFAULT_API_URL = "http://host.docker.internal:9000";
const DEFAULT_TOKEN = "";
const DEFAULT_VERDICTS_PATH = "";
const DEFAULT_WORKSPACE_ROOTS = ["/app", "/workspace"];

// per-process (= per-trial container) monotonic step counter
let tidCounter = 0;
const preToolDecisionByCallId = new Map();
const lastProcessResultBySession = new Map();

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function firstString(...vals) {
  for (const v of vals) {
    if (typeof v === "string" && v.length) return v;
  }
  return "";
}

function firstStringAllowEmpty(...vals) {
  for (const v of vals) {
    if (typeof v === "string") return v;
  }
  return undefined;
}

function mappedWriteInput(p) {
  const path = firstString(p.path, p.file_path, p.file, p.filename);
  let content = firstString(
    p.content, p.text, p.file_text, p.new_str, p.new_string, p.newText, p.new_text, p.data, p.body
  );
  if (!content && Array.isArray(p.edits)) {
    content = p.edits
      .map((e) =>
        e && typeof e === "object"
          ? firstString(e.newText, e.new_text, e.text, e.content)
          : ""
      )
      .filter(Boolean)
      .join("\n");
  }
  const mapped = { path, content };
  const oldText = firstString(p.oldText, p.old_text, p.old_str, p.old_string);
  if (oldText) mapped.oldText = oldText;
  const newText = firstStringAllowEmpty(p.newText, p.new_text, p.new_str, p.new_string);
  if (newText !== undefined) mapped.newText = newText;
  if (Array.isArray(p.edits)) mapped.edits = p.edits;
  return mapped;
}

function patchPaths(patchText) {
  const paths = [];
  for (const line of String(patchText || "").split(/\r?\n/)) {
    const m = line.match(/^\*\*\* (?:Update|Add|Delete) File:\s*(.+?)\s*$/);
    if (m && !paths.includes(m[1])) paths.push(m[1]);
    const move = line.match(/^\*\*\* Move to:\s*(.+?)\s*$/);
    if (move && !paths.includes(move[1])) paths.push(move[1]);
  }
  return paths;
}

// Map an OpenClaw tool call to the EnfGuard gate's tool_name + tool_input,
// mirroring the Tier B hook mapping so the frozen tool_mapper sees the
// vocabulary it was calibrated on. Unknown tools pass through so the gate's
// unknown-tool coverage tier sees them.
function enfToolInput(toolName, params) {
  const p = asObject(params);
  const name = String(toolName || "").toLowerCase();
  if (name === "apply_patch" || name === "applypatch") {
    const patch = firstString(p.patch, p.input, p.content, p.text);
    const paths = patchPaths(patch);
    return {
      tool: "write_file",
      input: {
        path: paths[0] || "",
        paths,
        content: patch,
        operation: "patch",
      },
    };
  }
  if (
    name === "exec" || name === "bash" || name === "shell" ||
    name === "run_command" || name === "execute" || name === "run" ||
    name === "terminal" || name.includes("bash") || name.includes("shell")
  ) {
    const command = firstString(p.command, p.cmd, p.script, p.input, p.code);
    if (!command) return { tool: "bash", input: { command: JSON.stringify(p) } };
    return { tool: "bash", input: { command } };
  }
  if (
    name === "read" || name === "read_file" || name === "view" || name === "cat" ||
    name === "file_read" || name === "fs_read" || name === "filesystem.read"
  ) {
    return {
      tool: "read_file",
      input: { path: firstString(p.path, p.file_path, p.file, p.filename) },
    };
  }
  if (
    name === "write" || name === "append" || name === "edit" || name === "patch" ||
    name === "write_file" || name === "code_edit" || name === "str_replace_editor" ||
    name === "str_replace_based_editor" || name === "text_editor"
  ) {
    return { tool: "write_file", input: mappedWriteInput(p) };
  }
  if (
    name === "web_fetch" || name === "web_search" ||
    name === "firecrawl_search" || name === "jina_reader_extract" ||
    name === "fetch" || name === "browser"
  ) {
    return {
      tool: "web_fetch",
      input: { url: firstString(p.url, p.uri, p.endpoint, p.query, p.q, p.targetUrl) },
    };
  }
  if (/memory|remember|memories/.test(name) && !/read|list|show|get|view|search/.test(name)) {
    return {
      tool: "memory_write",
      input: {
        ...p,
        path: firstString(p.path, p.file_path, "~/.openclaw/workspace/memory.json"),
        content: firstString(p.content, p.text, p.value, p.memory, p.data, JSON.stringify(p)),
      },
    };
  }
  if (name === "process" || name === "session" || name === "process_control") {
    return { tool: "process", input: p };
  }
  return { tool: String(toolName || "tool"), input: p };
}

function configuredWorkspaceRoots(value) {
  const raw = value ?? process.env.ENFGUARD_WORKSPACE_ROOTS;
  const values = Array.isArray(raw)
    ? raw
    : (typeof raw === "string" ? raw.split(",") : DEFAULT_WORKSPACE_ROOTS);
  const roots = values
    .map((v) => String(v || "").trim().replace(/\/+$/, ""))
    .filter((v) => v.startsWith("/") && v !== "");
  return [...new Set(roots)].slice(0, 8);
}

function gateConfig(pluginConfig, event) {
  // OpenClaw exposes the plugin's configured block via api.pluginConfig at
  // register time (see the bundled active-memory extension). The per-event
  // context.pluginConfig is not reliably populated, so prefer the captured
  // register-time config and fall back to the event only if absent.
  const config = asObject(pluginConfig ?? event?.context?.pluginConfig);
  if (config.enabled === false) return null;
  return {
    apiUrl: String(config.apiUrl || process.env.ENFGUARD_API_URL || DEFAULT_API_URL).replace(/\/+$/, ""),
    adminToken: String(config.adminToken || process.env.ENFGUARD_ADMIN_TOKEN || DEFAULT_TOKEN),
    failMode: String(config.failMode || "block"),
    sid: String(
      config.sid ||
      process.env.ENFGUARD_SID ||
      event?.context?.sessionKey ||
      event?.context?.sessionId ||
      "openclaw"
    ),
    blockApprovals: config.blockApprovals === true,
    verdictsPath: String(config.verdictsPath || DEFAULT_VERDICTS_PATH),
    workspaceRoots: configuredWorkspaceRoots(config.workspaceRoots),
  };
}

function logVerdict(cfg, record) {
  if (!cfg.verdictsPath) return;
  try {
    fs.appendFileSync(cfg.verdictsPath, JSON.stringify(record) + "\n");
  } catch {}
}

function stringifyResult(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function resultTextForGate(event) {
  if (event?.error) return String(event.error);
  const value = event?.result;
  if (value === undefined || value === null || typeof value === "string") {
    return stringifyResult(value);
  }
  if (typeof value !== "object") return String(value);

  // OpenClaw result objects often contain the same output both in `content`
  // (what the model sees) and in diagnostic `details` fields. Classifying the
  // whole object double-counts old process output and patch diffs.
  if (Array.isArray(value.content)) {
    const visible = value.content
      .map((part) => typeof part === "string" ? part : firstString(part?.text, part?.content))
      .filter(Boolean)
      .join("\n");
    if (visible) return visible;
  }
  const direct = firstString(value.output, value.stdout, value.text, value.message);
  if (direct) return direct;
  return stringifyResult(value);
}

function processResultKey(cfg, mapped) {
  if (mapped.tool !== "process") return "";
  const p = asObject(mapped.input);
  const processId = firstString(p.sessionId, p.session_id, p.processId, p.process_id, p.id);
  return `${cfg.sid}:${processId || "default"}`;
}

function resultExitCode(event) {
  if (event?.error) return 1;
  const r = event?.result;
  if (r && typeof r === "object") {
    const raw = r.exit_code ?? r.exitCode ?? r.code;
    const n = Number(raw);
    if (Number.isFinite(n)) return n;
  }
  return 0;
}

async function postJson(url, adminToken, sid, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-admin-token": adminToken,
        "x-session-id": sid,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const data = await res.json().catch(() => ({}));
    return { ok: res.ok, status: res.status, data };
  } finally {
    clearTimeout(timer);
  }
}

export const pluginDefinition = {
  id: "enfguard-gate",
  name: "AgentEnf Gate",
  description:
    "Pre-tool gate and post-tool result posting backed by the local EnfGuard proxy.",
  register(api) {
    const registeredPluginConfig = api?.pluginConfig;
    const initial = gateConfig(registeredPluginConfig, {});
    if (initial && !initial.adminToken) throw new Error("Set ENFGUARD_ADMIN_TOKEN or plugin adminToken");
    api.on(
      "before_tool_call",
      async (event, context) => {
        event = { ...event, context: context ?? event.context };
        const cfg = gateConfig(registeredPluginConfig, event);
        if (!cfg) return;

        const mapped = enfToolInput(event.toolName, event.params);
        tidCounter += 1;
        let tid = null;
        const call_id = String(
          event.toolCallId || event.id || event.callId || event.tool_call_id || `${cfg.sid}-${tidCounter}`
        );

        const t0 = Date.now();
        let decision = "allow";
        let effective = "allow";
        let reason = "";
        let httpStatus = 0;
        let rawResponse = null;
        let policyDecision = "allow";
        let runtimeDecision = "proceed";
        // Where an eventual Block came from. A fail-closed Block is correct
        // security behaviour, but it is NOT an enforcement decision: no policy
        // evaluated the call. Recording it as an ordinary Block manufactures an
        // intervention and inflates every downstream count. Scoring must be able
        // to separate the two, so the source is written into the verdict record
        // rather than inferred from the reason string.
        //   "policy"      the pack evaluated the call and returned a verdict
        //   "fail_closed" the gate could not be reached or errored, failMode applied
        let verdictSource = "policy";
        try {
          const res = await postJson(
            `${cfg.apiUrl}/v1/tool_execute`,
            cfg.adminToken,
            cfg.sid,
            {
              sid: cfg.sid,
              call_id,
              tool_name: mapped.tool,
              tool_input: mapped.input,
              workspace_roots: cfg.workspaceRoots,
              decision_schema_version: 1,
            },
            120000
          );
          httpStatus = res.status;
          rawResponse = res.data;
          tid = res.data?.tid ?? null;
          if (!res.ok) {
            decision = "gate_http_error";
            verdictSource = "fail_closed";
            effective = cfg.failMode === "block" ? "block" : "allow";
            reason = `EnfGuard proxy returned HTTP ${res.status}`;
          } else {
            if (!["allow", "block"].includes(res.data?.decision)) {
              throw new Error("Invalid gate decision");
            }
            decision = res.data.decision;
            reason = String(res.data?.reason || "");
            policyDecision = String(
              res.data?.decision_trace?.policy_decision || decision
            ).toLowerCase();
            runtimeDecision = String(
              res.data?.decision_trace?.runtime_decision || "proceed"
            );
            effective = decision;
            if (decision !== "block" && policyDecision === "approve") {
              // Benign utility profile: approvals proceed but stay logged,
              // unless blockApprovals is explicitly enabled.
              effective = cfg.blockApprovals ? "block" : "allow";
            }
            if (decision !== "block" && policyDecision === "warn") {
              effective = "allow";
            }
          }
        } catch (error) {
          decision = "gate_unreachable";
          verdictSource = "fail_closed";
          effective = cfg.failMode === "block" ? "block" : "allow";
          reason = `EnfGuard proxy unavailable: ${error instanceof Error ? error.message : String(error)}`;
        }
        const gateLatencyMs = Date.now() - t0;
        if (preToolDecisionByCallId.size >= 4096) preToolDecisionByCallId.delete(preToolDecisionByCallId.keys().next().value);
        preToolDecisionByCallId.set(`${cfg.sid}:${call_id}`, {
          policy_decision: policyDecision,
          runtime_decision: runtimeDecision,
          effective_verdict: effective,
          effect_executed: effective === "block" ? false : null,
          verdict_source: verdictSource,
        });

        logVerdict(cfg, {
          ts: new Date().toISOString(),
          phase: "before_tool_call",
          sid: cfg.sid,
          tid,
          call_id,
          tool: String(event.toolName || ""),
          mapped_tool: mapped.tool,
          tool_input_preview: JSON.stringify(mapped.input).slice(0, 500),
          decision,
          policy_decision: policyDecision,
          runtime_decision: runtimeDecision,
          effective_verdict: effective,
          effect_executed: effective === "block" ? false : null,
          verdict_source: verdictSource,
          infrastructure_fault: verdictSource !== "policy",
          reason,
          http_status: httpStatus,
          gate_latency_ms: gateLatencyMs,
          raw: rawResponse,
        });

        if (effective === "block") {
          return {
            block: true,
            blockReason: `[AgentEnf] blocked ${mapped.tool}: ${reason || decision}`,
          };
        }
      },
      { priority: 100, timeoutMs: 130000 }
    );

    api.on(
      "after_tool_call",
      async (event, context) => {
        event = { ...event, context: context ?? event.context };
        const cfg = gateConfig(registeredPluginConfig, event);
        if (!cfg) return;

        const mapped = enfToolInput(event.toolName, event.params);
        tidCounter += 1;
        let tid = null;
        const call_id = String(
          event.toolCallId || event.id || event.callId || event.tool_call_id || `${cfg.sid}-result-${tidCounter}`
        );
        let tool_response = resultTextForGate(event);
        let resultDuplicate = false;
        const resultKey = processResultKey(cfg, mapped);
        if (resultKey && tool_response && lastProcessResultBySession.get(resultKey) === tool_response) {
          tool_response = "";
          resultDuplicate = true;
        } else if (resultKey && tool_response) {
          if (lastProcessResultBySession.size >= 256) lastProcessResultBySession.delete(lastProcessResultBySession.keys().next().value);
          lastProcessResultBySession.set(resultKey, tool_response.slice(0, 200_000));
        }
        const toolExecution = preToolDecisionByCallId.get(`${cfg.sid}:${call_id}`) || {
          effect_executed: true,
          runtime_decision: "observed_after_execution",
        };
        toolExecution.effect_executed = true;
        preToolDecisionByCallId.delete(`${cfg.sid}:${call_id}`);

        const t0 = Date.now();
        let decision = "allow";
        let reason = "";
        let httpStatus = 0;
        let rawResponse = null;
        let policyDecision = "allow";
        let runtimeDecision = "observed_after_execution";
        try {
          const res = await postJson(
            `${cfg.apiUrl}/v1/tool_result`,
            cfg.adminToken,
            cfg.sid,
            {
              sid: cfg.sid,
              call_id,
              tool_name: mapped.tool,
              tool_input: mapped.input,
              tool_response,
              exit_code: resultExitCode(event),
              workspace_roots: cfg.workspaceRoots,
              decision_schema_version: 1,
              tool_execution: toolExecution,
              result_payload_scope: "model_visible_content",
              result_duplicate: resultDuplicate,
            },
            120000
          );
          httpStatus = res.status;
          rawResponse = res.data;
          tid = res.data?.tid ?? null;
          if (!["allow", "block"].includes(res.data?.decision)) {
              throw new Error("Invalid gate decision");
            }
            decision = res.data.decision;
          reason = String(res.data?.reason || "");
          policyDecision = String(
            res.data?.decision_trace?.result_gate?.policy_decision || decision
          ).toLowerCase();
          runtimeDecision = "observed_after_execution";
        } catch (error) {
          decision = "result_post_failed";
          reason = String(error instanceof Error ? error.message : error);
        }
        logVerdict(cfg, {
          ts: new Date().toISOString(),
          phase: "after_tool_call",
          sid: cfg.sid,
          tid,
          call_id,
          tool: String(event.toolName || ""),
          mapped_tool: mapped.tool,
          decision,
          policy_decision: policyDecision,
          runtime_decision: runtimeDecision,
          effective_verdict: "observe",
          effect_executed: true,
          result_enforcement_supported: false,
          reason,
          http_status: httpStatus,
          result_latency_ms: Date.now() - t0,
          exit_code: resultExitCode(event),
          result_preview: tool_response.slice(0, 300),
          result_payload_scope: "model_visible_content",
          result_duplicate: resultDuplicate,
          raw: rawResponse,
        });
      },
      { priority: 100, timeoutMs: 130000 }
    );
  },
};
