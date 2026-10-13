export function enforcementDenial({tool, reason, decision, source, response, callId, sessionId}) {
  const trace = response?.decision_trace;
  const rules = [...new Set((trace?.policy_verdicts || [])
    .filter(v => ['BlockToolCall', 'BlockRequest', 'Approve'].includes(v.action))
    .map(v => v.category).filter(v => typeof v === 'string' && v.length))];
  const kind = source === 'fail_closed' ? 'service_failure'
    : trace?.policy_decision === 'approve' ? 'approval_block' : 'policy_block';
  const record = {version:1, kind, tool, rules, reason:reason || decision,
    callId, sessionId, timepoint:response?.tid ?? null};
  const title = kind === 'service_failure' ? 'AgentEnf stopped this tool because enforcement was unavailable'
    : kind === 'approval_block' ? 'AgentEnf stopped this tool because approval was not granted'
    : 'Blocked by AgentEnf';
  return `[AgentEnf] ${title}\nTool: ${tool}\nRule: ${rules.join(', ') || 'No rule identifier supplied'}\nReason: ${record.reason}\nThis invocation did not execute. This is runtime enforcement, not a model refusal.\n[EnfAgent enforcement] ${JSON.stringify(record)}`;
}
