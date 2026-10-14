import assert from "node:assert/strict";
import { FIXTURE_TRACES } from "./fixtures.js";
import {
  classifierAccount,
  decisionAccount,
  enforcerEventLog,
  eventSentence,
  eventsInOrder,
  groupSessions,
  isAfterTool,
  isToolGate,
  predicateMatched,
  sessionIdFromRecords,
  storyLine,
  tracesForFilter,
  turnCaption,
  verdictKind,
} from "./traceUtils.js";

assert.equal(verdictKind("ApproveToolCall"), "approval");
assert.equal(verdictKind("WarnToolCall"), "warn");
assert.notEqual(verdictKind("ApproveToolCall"), verdictKind("WarnToolCall"));
assert.equal(verdictKind("BlockToolCall"), "block");
assert.equal(verdictKind("tool_allow"), "allow");
assert.equal(verdictKind(""), "allow");

const closed = {
  predicate: "secret_value_judge",
  raw_score: 1,
  score: 1,
  fail_mode: "closed",
  reason: "judge_unavailable: TimeoutError",
};
assert.equal(classifierAccount(closed).state, "failed");
assert.equal(predicateMatched(closed), false);

const predicates = FIXTURE_TRACES.find((trace) => trace.tid === 3);
assert.equal(classifierAccount(predicates.predicate_rows[0]).state, "local");
assert.equal(predicateMatched(predicates.predicate_rows[0]), false);
assert.equal(predicateMatched(predicates.predicate_rows[1]), true);
assert.equal(classifierAccount(predicates.predicate_rows[2]).state, "model");
assert.equal(predicateMatched(predicates.predicate_rows[2]), true);

const failure = FIXTURE_TRACES.find((trace) => trace.tid === 4);
assert.equal(predicateMatched(failure.predicate_rows[1]), false);
assert.equal(classifierAccount(failure.predicate_rows[1]).state, "failed");

const earlier = FIXTURE_TRACES.find((trace) => trace.tid === 11);
const blocked = FIXTURE_TRACES.find((trace) => trace.tid === 12);
const afterTool = FIXTURE_TRACES.find((trace) => trace.tid === 21);

assert.equal(sessionIdFromRecords(blocked.session_records), "fixture-temporal");
assert.equal(isAfterTool(afterTool.session_records[1]), true);
assert.equal(isToolGate(afterTool.session_records[0]), true);
assert.equal(isToolGate(afterTool.session_records[1]), false);

const gate = decisionAccount(blocked);
assert.equal(gate.effective, "tool_block");
assert.equal(gate.blockAfterTool, false);
assert.equal(gate.requested[0].category, "untrusted_instruction_delete");

const late = decisionAccount(afterTool);
assert.equal(late.effective, "tool_allow");
assert.equal(late.blockAfterTool, true);
assert.equal(late.differs, true);

const logged = enforcerEventLog(earlier);
const loggedLines = logged.flatMap((entry) => entry.groups.flatMap((group) => group.lines.map((line) => line.text)));
assert.ok(loggedLines.some((line) => line.startsWith("Turn context")));
assert.ok(loggedLines.some((line) => line.startsWith("Tool result:")));
assert.ok(loggedLines.some((line) => line.startsWith("Untrusted source:")));
assert.ok(loggedLines.some((line) => line.startsWith("Classified ")));
assert.equal(storyLine(late).headline, "Allowed · blocked too late");
assert.equal(storyLine(gate).headline, "Blocked");
assert.equal(turnCaption(afterTool, afterTool).subtitle, "Allowed · blocked too late");
assert.equal(turnCaption(blocked, blocked).subtitle, "deletion follows an untrusted instruction-like result");
assert.equal(turnCaption(blocked, blocked).action, "tool_block");

const hidden = eventSentence(
  { name: "ToolPlanned", args: [21, "rm-1", "bash", "rm notes.txt"] },
  { redact: true },
);
assert.equal(hidden, "Planned bash: …");
assert.equal(hidden.includes("rm notes.txt"), false);
assert.equal(
  eventSentence({ name: "ToolCall", args: [21, "rm-1", "bash", "rm notes.txt"] }),
  "Proposed bash: rm notes.txt",
);
for (const event of [
  { name: "Message", args: [21, "user", "secret", 1] },
  { name: "ToolResult", args: [21, "rm-1", "secret", 0] },
  { name: "Completion", args: [21, "secret", 1] },
]) {
  assert.equal(eventSentence(event, { redact: true }).includes("secret"), false);
}

const filtered = tracesForFilter(
  [
    { tid: 11, ts: 1, sid: "fixture-temporal", action: "tool_result_allow" },
    { tid: 12, ts: 2, sid: "fixture-temporal", action: "tool_block" },
    { tid: 3, ts: 3, sid: "fixture-predicates", action: "response_blocked" },
    { tid: 4, ts: 4, sid: "fixture-failure", action: "allowed" },
  ],
  "block",
);
assert.deepEqual(filtered.traces.map((turn) => turn.tid), [11, 12, 3]);
assert.deepEqual(filtered.contextTids, [11]);
const unscoped = tracesForFilter([
  { tid: 1, ts: 1, action: "tool_allow" },
  { tid: 2, ts: 2, action: "tool_block" },
], "block");
assert.deepEqual(unscoped.traces.map((turn) => turn.tid), [2]);
assert.deepEqual(unscoped.contextTids, []);

const steps = eventsInOrder(earlier);
assert.ok(steps.some((step) => step.title === "Tool result" && step.body.includes("delete backups")));
assert.ok(steps.some((step) => step.title === "Untrusted source: web_fetch"));
assert.ok(steps.some((step) => step.title.includes("instruction_like")));
assert.equal(steps.some((step) => step.title === "Clock"), false);

const groups = groupSessions([blocked, earlier, predicates]);
const temporal = groups.find((group) => group.id === "fixture-temporal");
assert.deepEqual(temporal.turns.map((turn) => turn.tid), [11, 12]);

console.log("traceUtils tests passed");
