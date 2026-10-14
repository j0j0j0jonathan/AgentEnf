// Pure, stateless helpers shared across the trace and console views.
// Extracted from App.jsx so the view components stay focused on rendering and
// these stay independently testable. No React imports on purpose.

export function rangeStyle(value, min = 0, max = 1) {
  const number = Number(value);
  const lower = Number(min);
  const upper = Number(max);
  const percent = upper === lower ? 0 : ((number - lower) / (upper - lower)) * 100;
  return { "--range-progress": `${Math.min(100, Math.max(0, percent))}%` };
}

export function formatEvent(event, options = {}) {
  const args = (event?.args || []).map((value) => formatEventArg(value, options)).join(", ");
  return `${event?.name || "Event"}(${args})`;
}

export function formatEventArg(value, options = {}) {
  const redact = Boolean(options.redact);
  if (typeof value === "string") {
    if (redact && value.length > 24) return JSON.stringify("…");
    const trimmed = value.length > 120 ? `${value.slice(0, 120)}…` : value;
    return JSON.stringify(trimmed);
  }
  if (value && typeof value === "object") {
    const text = JSON.stringify(value);
    if (redact) return "\"…\"";
    return text.length > 120 ? `${text.slice(0, 120)}…` : text;
  }
  return String(value);
}

export function formatEventFull(event) {
  const args = (event?.args || []).map((value) => (
    typeof value === "string" || (value && typeof value === "object")
      ? JSON.stringify(value)
      : String(value)
  )).join(", ");
  return `${event?.name || "Event"}(${args})`;
}

const EVENT_GROUP_META = [
  ["inbound", "Inbound", "Sent to EnfGuard"],
  ["verdict_events", "Verdict", "Returned by EnfGuard"],
  ["outbound", "Outbound", "Sent to EnfGuard"],
];

function eventText(value, redact) {
  if (value == null || value === "") return "";
  if (typeof value === "object") return redact ? "…" : shortText(JSON.stringify(value), 140);
  const text = String(value);
  if (redact && text.trim()) return "…";
  return shortText(text, 140);
}

// One sentence per signature event. The function-call form stays available
// as `full` for the operator who wants the raw arguments.
export function eventSentence(event, options = {}) {
  const redact = Boolean(options.redact);
  const name = String(event?.name || "Event");
  const args = Array.isArray(event?.args) ? event.args : [];
  if (name === "Turn") {
    const session = eventText(args[2], redact);
    return session && session !== "…" ? `Turn context · ${session}` : "Turn context";
  }
  if (name === "ToolPlanned" || name === "ToolCall") {
    const verb = name === "ToolPlanned" ? "Planned" : "Proposed";
    const tool = eventText(args[2], false) || "tool";
    const body = eventText(args[3], redact);
    return body ? `${verb} ${tool}: ${body}` : `${verb} ${tool}`;
  }
  if (name === "ToolResult") {
    const body = eventText(args[2], redact);
    return body ? `Tool result: ${body}` : "Tool result";
  }
  if (name === "Message") {
    const role = eventText(args[1], false) || "message";
    const body = eventText(args[2], redact);
    return body ? `${role} message: ${body}` : `${role} message`;
  }
  if (name === "Completion" || name === "CompletionRedacted" || name === "CompletionReleased") {
    const body = eventText(args[1], redact);
    const label = name === "Completion" ? "Model response" : name;
    return body ? `${label}: ${body}` : label;
  }
  if (name === "Classify") {
    const dimension = eventText(args[2], false) || "dimension";
    const level = eventText(args[3], redact);
    return level ? `Classified ${dimension} as ${level}` : `Classified ${dimension}`;
  }
  if (name === "Untrusted") {
    const source = eventText(args[1], false) || "unspecified";
    return `Untrusted source: ${source}`;
  }
  if (name === "Block" || name === "Warn" || name === "Approve") {
    const verb = name === "Block" ? "Blocked" : name === "Warn" ? "Warned" : "Asked for approval";
    const phase = eventText(args[1], false);
    const reason = eventText(args[3], false) || eventText(args[2], false);
    const where = phase ? ` the ${phase}` : "";
    return reason ? `${verb}${where}: ${reason}` : `${verb}${where}`;
  }
  return formatEvent(event, options);
}

export function enforcerEventLog(trace, options = {}) {
  return recordsInOrder(trace).map((record) => ({
    time: formatClock(record.ts),
    action: String(record.action || ""),
    groups: EVENT_GROUP_META.map(([key, label, hint]) => {
      const events = Array.isArray(record[key]) ? record[key] : [];
      return {
        key,
        label,
        hint,
        lines: events.filter((event) => event && typeof event === "object").map((event) => ({
          text: eventSentence(event, options),
          full: formatEventFull(event),
        })),
      };
    }).filter((group) => group.lines.length),
  })).filter((entry) => entry.groups.length);
}

// The line an operator should trust: the runtime result, with a late block
// named in the same sentence as the allow that already happened.
export function storyLine(account) {
  const kind = account?.effectiveKind || "allow";
  const verb = { block: "Blocked", approval: "Needs approval", warn: "Warned", allow: "Allowed" }[kind] || "Allowed";
  const late = Boolean(account?.blockAfterTool) && kind !== "block";
  return {
    headline: late ? `${verb} · blocked too late` : verb,
    mark: account?.effective || "",
    late,
  };
}

export function turnCaption(turn, detail) {
  const title = turn?.tool_name || `Turn ${turn?.tid ?? ""}`;
  if (!detail) {
    const fired = Array.isArray(turn?.fired_predicates) ? turn.fired_predicates : [];
    const afterTool = String(turn?.action || "").startsWith("tool_result");
    const subtitle = afterTool
      ? "Logged after the tool ran"
      : fired.length
        ? fired.slice(0, 2).join(", ")
        : verdictLabel(turn?.action);
    return { action: turn?.action || "", title, subtitle };
  }
  const account = decisionAccount(detail);
  const story = storyLine(account);
  const reason = (account.requested || []).map((verdict) => verdict.reason).find(Boolean) || "";
  const fired = Array.isArray(turn?.fired_predicates) ? turn.fired_predicates : [];
  let subtitle = story.headline;
  if (!story.late && reason) subtitle = reason;
  else if (!story.late && fired.length) subtitle = fired.slice(0, 2).join(", ");
  return { action: story.mark || account.effective || turn?.action || "", title, subtitle };
}

// Keep earlier turns of a session that contains a match, so a temporal block
// still shows the turn that came before it. Those earlier turns are context.
export function tracesForFilter(list, filter) {
  const traces = Array.isArray(list) ? list : [];
  if (!filter || filter === "all") return { traces, contextTids: [] };
  const match = (entry) => verdictKind(entry?.action) === filter;
  const matches = traces.filter(match);
  const contextTids = [];
  const kept = [];
  for (const entry of traces) {
    if (match(entry)) {
      kept.push(entry);
      continue;
    }
    const sid = sessionIdOf(entry);
    if (!sid) continue;
    const providesContext = matches.some((other) => {
      if (sessionIdOf(other) !== sid) return false;
      const earlierTs = Number(entry?.ts || 0) < Number(other?.ts || 0);
      const sameTimeEarlierId = Number(entry?.ts || 0) === Number(other?.ts || 0) && Number(entry?.tid) < Number(other?.tid);
      return earlierTs || sameTimeEarlierId;
    });
    if (providesContext) {
      kept.push(entry);
      contextTids.push(entry.tid);
    }
  }
  return { traces: kept, contextTids };
}

export function phaseTimingLabel(phase) {
  // Old traces only carry `wall_ms`. New traces carry `enfguard_ms`
  // (engine) and `judge_ms` (HTTP) separately. When the breakdown is
  // available, surface it inline so the user sees where the time went.
  const engine = Number(phase.enfguard_ms || 0);
  const judge = Number(phase.judge_ms || 0);
  const model = Number(phase.upstream_ms || 0);
  const total = Number(phase.wall_ms || engine + judge + model);
  if (engine || judge || model) {
    const parts = [`enfguard ${engine}ms`, `judge ${judge}ms`];
    if (model) parts.push(`model ${model}ms`);
    return `${total}ms (${parts.join(" · ")})`;
  }
  return `${total}ms`;
}

// Map a raw verdict/action string to one of the four states the console shows.
// Approval is its own state. Warn-mode and approval used to share one pill.
export function verdictKind(action) {
  const text = String(action || "").toLowerCase();
  if (!text) return "allow";
  if (text.includes("block")) return "block";
  if (text.includes("approv")) return "approval";
  if (text.includes("warn")) return "warn";
  return "allow";
}

export function verdictLabel(action) {
  const text = String(action || "");
  if (!text) return "No verdict";
  const kind = verdictKind(text);
  if (kind === "block") return "Block";
  if (kind === "approval") return "Approval";
  if (kind === "warn") return "Warn";
  return "Allow";
}

export function phaseLabel(phase) {
  if (phase === "inbound") return "User message";
  if (phase === "outbound") return "Model response";
  if (phase === "tool") return "Tool call";
  return phase ? String(phase) : "Phase";
}

export function formatClock(ts) {
  const value = Number(ts);
  if (!Number.isFinite(value) || value <= 0) return "";
  const date = new Date(value > 1e12 ? value : value * 1000);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function shortText(value, limit = 160) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  if (text.length <= limit) return text;
  return `${text.slice(0, limit).trim()}…`;
}

export function sessionIdFromRecords(records) {
  for (const record of records || []) {
    for (const group of ["inbound", "outbound"]) {
      for (const event of record?.[group] || []) {
        const args = event?.args || [];
        if (event?.name === "Turn" && args.length >= 3 && args[2]) return String(args[2]);
        if (event?.name === "Session" && args[0]) return String(args[0]);
      }
    }
  }
  return "";
}

export function sessionIdOf(entry) {
  if (!entry) return "";
  if (entry.sid) return String(entry.sid);
  return sessionIdFromRecords(entry.session_records);
}

const EVENT_GROUPS = ["inbound", "verdict_events", "outbound"];

export function recordsInOrder(trace) {
  return [...(trace?.session_records || [])].sort(
    (left, right) => Number(left?.ts || 0) - Number(right?.ts || 0),
  );
}

export function isAfterTool(record) {
  return String(record?.action || "").startsWith("tool_result");
}

export function isToolGate(record) {
  const action = String(record?.action || "");
  return action.startsWith("tool_") && !action.startsWith("tool_result");
}

// A classifier failure carries fail_mode. Its score is the fallback, not a
// judgement that the content matched.
export function classifierAccount(row) {
  const fail = String(row?.fail_mode || "").trim().toLowerCase();
  if (fail) {
    return {
      state: "failed",
      label: "Classifier failed",
      detail: `Fail mode ${fail}. The score is the fallback for that failure, not a positive classification.`,
    };
  }
  const prompt = String(row?.judge_prompt || "").trim();
  const reply = String(row?.judge_raw_reply || "").trim();
  if (prompt || reply) {
    return {
      state: "model",
      label: "Model classifier",
      detail: "An external model returned this score.",
    };
  }
  return {
    state: "local",
    label: "Local check",
    detail: "No model reply was recorded. This covers keyword checks and Python predicates.",
  };
}

export function predicateMatched(row) {
  if (classifierAccount(row).state === "failed") return false;
  return Number(row?.score || 0) >= 0.5;
}

export function describeEvent(event) {
  const name = String(event?.name || "Event");
  const args = Array.isArray(event?.args) ? event.args : [];
  if (name === "ToolPlanned" || name === "ToolCall") {
    return {
      kind: "tool",
      title: String(args[2] || name),
      body: String(args[3] || ""),
      callId: String(args[1] || ""),
      pending: name === "ToolPlanned",
    };
  }
  if (name === "ToolResult") {
    return {
      kind: "result",
      title: "Tool result",
      body: String(args[2] || ""),
      callId: String(args[1] || ""),
      exitCode: args.length >= 4 ? args[3] : "",
    };
  }
  if (name === "Message") {
    return {
      kind: "message",
      title: `${args[1] || "message"} message`,
      body: String(args[2] || ""),
    };
  }
  if (name === "Completion" || name === "CompletionRedacted" || name === "CompletionReleased") {
    return {
      kind: "message",
      title: name === "Completion" ? "Model response" : name,
      body: String(args[1] || ""),
    };
  }
  if (name === "Classify") {
    return {
      kind: "fact",
      title: `Classify ${args[2] || "dimension"} = ${args[3] || ""}`,
      body: "",
      callId: String(args[1] || ""),
    };
  }
  if (name === "Untrusted") {
    return {
      kind: "fact",
      title: `Untrusted source: ${args[1] || "unspecified"}`,
      body: "",
    };
  }
  if (name === "Block" || name === "Warn" || name === "Approve") {
    return {
      kind: "verdict",
      title: `${name} · ${args[1] || "phase"}`,
      body: [args[2], args[3]].filter((part) => part !== undefined && part !== "").join(" — "),
    };
  }
  return { kind: "other", title: name, body: formatEvent(event) };
}

const HISTORY_KINDS = new Set(["tool", "result", "message", "fact", "verdict"]);

export function eventsInOrder(trace) {
  const steps = [];
  for (const record of recordsInOrder(trace)) {
    const stamp = formatClock(record.ts);
    for (const group of EVENT_GROUPS) {
      for (const event of record?.[group] || []) {
        const described = describeEvent(event);
        if (!HISTORY_KINDS.has(described.kind)) continue;
        steps.push({
          ...described,
          time: stamp,
          afterTool: isAfterTool(record),
          recordAction: String(record.action || ""),
        });
      }
    }
  }
  return steps;
}

export function requestedVerdicts(trace) {
  const found = [];
  const seen = new Set();
  function push(verdict, source) {
    if (!verdict || typeof verdict !== "object") return;
    const action = String(verdict.action || "");
    if (!action) return;
    const key = `${source}|${action}|${verdict.category || ""}|${verdict.reason || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({
      action,
      category: String(verdict.category || ""),
      reason: String(verdict.reason || ""),
      source,
    });
  }
  for (const record of recordsInOrder(trace)) {
    const source = isAfterTool(record) ? "after-tool" : isToolGate(record) ? "tool-gate" : "record";
    for (const verdict of record.verdicts || []) push(verdict, source);
  }
  if (!found.length) {
    for (const phase of trace?.phases || []) {
      for (const verdict of phase.verdicts || []) push(verdict, phase.phase || "phase");
    }
  }
  return found;
}

export function runtimeAction(trace) {
  const records = recordsInOrder(trace);
  const gate = records.find(isToolGate);
  if (gate?.action) return String(gate.action);
  const other = records.find((record) => record?.action && !isAfterTool(record));
  if (other?.action) return String(other.action);
  const phase = (trace?.phases || []).find((item) => item?.action);
  if (phase?.action) return String(phase.action);
  const last = records.at(-1);
  return last?.action ? String(last.action) : "";
}

export function decisionAccount(trace) {
  const records = recordsInOrder(trace);
  const requested = requestedVerdicts(trace);
  const effective = runtimeAction(trace);
  const afterToolRecords = records.filter(isAfterTool);
  const blockAfterTool = afterToolRecords.some((record) => {
    if (verdictKind(record.action) === "block") return true;
    return (record.verdicts || []).some((verdict) => verdictKind(verdict.action) === "block");
  });
  const effectiveKind = verdictKind(effective);
  const requestedKinds = requested.map((verdict) => verdictKind(verdict.action));
  const differs = requestedKinds.some((kind) => kind !== "allow" && kind !== effectiveKind);
  return {
    effective,
    effectiveKind,
    requested,
    differs,
    hasToolGate: records.some(isToolGate),
    hasAfterTool: afterToolRecords.length > 0,
    blockAfterTool,
  };
}

export function groupSessions(traces) {
  const groups = new Map();
  for (const entry of traces || []) {
    const sid = sessionIdOf(entry) || "";
    const key = sid || "__unscoped__";
    if (!groups.has(key)) {
      groups.set(key, { id: sid, key, turns: [], latest: 0 });
    }
    const group = groups.get(key);
    group.turns.push(entry);
    group.latest = Math.max(group.latest, Number(entry.ts || 0));
  }
  for (const group of groups.values()) {
    group.turns.sort((left, right) => Number(left.ts || 0) - Number(right.ts || 0) || Number(left.tid) - Number(right.tid));
  }
  return [...groups.values()].sort((left, right) => right.latest - left.latest);
}
