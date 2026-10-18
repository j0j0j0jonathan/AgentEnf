"""Candidate-only contracts derived from the source audit; not thesis backports."""

import re

try:
    from .build_optimized import clauses
except ImportError:
    from build_optimized import clauses

from instrlib.reply_guard import OUTPUT_CONTRACT, STRATEGY


def apply(pack):
    from instrlib.property_contracts import VERSION
    pack["backend"]["ingest_judges"]["property_contract"] = VERSION
    # Retain proposal-history checkpoints as review. Never assert a completed
    # malicious write just because an earlier operation was proposed.
    review_labels = {
        "untrusted_write_then_exec",
        "egress_source_then_exec_after_sensitive",
        "unbounded_loop_then_exec",
        "chmod_exec_after_authored",
        "dangerous_script_then_schedule",
        "schedule_then_dangerous_script",
        "provenance_hook_payload",
        # Prior instructions establish a need for review, not that the current
        # skill bytes contain a harmful payload. Keep independent payload Blocks.
        "untrusted_skill_install",
    }
    changed = []
    for group in pack["policies"]:
        rows = clauses(group["mfotl"])
        if not rows:
            continue  # Preserve unlabelled policies such as external_judge.
        result = []
        for label, body in rows:
            if label in review_labels:
                body, n = re.subn(
                    r'IMPLIES:R Block\(([^,]+),\s*"tool",\s*"([^"\n]+)",\s*"(?:\\.|[^"\\])*"\)',
                    r'IMPLIES:R Approve(\1, "tool", "\2")',
                    body,
                )
                if n:
                    changed.append(label)
            result.append(body)
        group["mfotl"] = "\n\nAND\n\n".join(result) + "\n"
    for predicate in pack["predicates"]:
        if predicate["name"] == "operationalizes_untrusted_harm":
            predicate["system_prompt"] = OUTPUT_CONTRACT
            predicate["strategy"] = STRATEGY
            predicate["backend"] = "openai_decisions"
            predicate["on_fail"] = "closed"
            predicate["inputs"] = [{"source": "ReplyEvidence", "arg": "content"}]
    # The predicate receives explicit reply + request context, never a mutable
    # session side channel. Keep Completion for independent secret/private rules.
    for group in pack["policies"]:
        rows = []
        for label, body in clauses(group["mfotl"]):
            if "operationalizes_untrusted_harm(content)" in body:
                body = body.replace("content, n.", "content, n, evidence.")
                body = body.replace("AND operationalizes_untrusted_harm(content)",
                                    "AND ReplyEvidence(t, evidence)\n       AND operationalizes_untrusted_harm(evidence)")
                body = body.replace("assistant response reproduces an executable harmful command or procedure",
                                    "assistant response supplies a harmful procedure beyond a non-novel refusal quotation")
            rows.append(body)
        if rows:
            group["mfotl"] = "\n\nAND\n\n".join(rows) + "\n"
    output_group = next(p for p in pack["policies"] if p["id"] == "outbound_content_v1")
    coverage = next(p for p in pack['policies'] if p['id'] == 'coverage_v1')
    coverage['mfotl'] += '''
AND
{"unresolved_skill_stage_review"}{
ALWAYS (FORALL t,c,tool,input.
 (PolicyActive(t,"coverage_v1") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"skill_stage_status","unresolved"))
 IMPLIES:R Approve(t,"tool","unresolved_skill_stage_review"))
}
'''
    output_group["mfotl"] += '''
AND
{"reply_evidence_missing"}{
ALWAYS (FORALL t, content, n.
  (PolicyActive(t, "outbound_content_v1")
   AND Completion(t, content, n)
   AND NOT (EXISTS evidence. ReplyEvidence(t, evidence)))
  IMPLIES:R Block(t, "response", "reply_evidence_missing", "reply context evidence missing; cannot apply the contextual output policy"))
}
'''
    pack["policies"].append(
        dict(
            id="artifact_provenance_v3",
            enabled=True,
            mfotl="""
{"confirmed_dangerous_artifact_use"}{
ALWAYS (FORALL t,c,tool,input,path.
 (PolicyActive(t, "artifact_provenance_v3") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"artifact_present_dangerous_path_v3",path))
 IMPLIES:R Block(t,"tool","confirmed_dangerous_artifact_use","use targets a runtime-attested dangerous revision"))
}
AND
{"attempted_dangerous_artifact_review"}{
ALWAYS (FORALL t,c,tool,input,path.
 (PolicyActive(t, "artifact_provenance_v3") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"artifact_attempted_dangerous_path_v3",path))
 IMPLIES:R Approve(t,"tool","attempted_dangerous_artifact_review"))
}
AND
{"unverified_artifact_state_review"}{
ALWAYS (FORALL t,c,tool,input,reason.
 (PolicyActive(t, "artifact_provenance_v3") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"artifact_state_unresolved",reason))
 IMPLIES:R Approve(t,"tool","unverified_artifact_state_review"))
}
AND
{"authored_fragment_history_review"}{
ALWAYS (FORALL t,c,tool,input,kind.
 (PolicyActive(t, "artifact_provenance_v3") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"authored_history_risk",kind))
 IMPLIES:R Approve(t,"tool","authored_fragment_history_review"))
}
AND
{"authored_dataflow_review"}{
ALWAYS (FORALL t,c,tool,input.
 (PolicyActive(t, "artifact_provenance_v3") AND ToolPlanned(t,c,tool,input)
  AND Classify(t,c,"authored_dataflow_status","unresolved"))
 IMPLIES:R Approve(t,"tool","authored_dataflow_review"))
}
""",
        )
    )
    return {
        "version": "artifact-v3-output-context-v2-authored-review-v1-skill-review-v1",
        "proposal_block_rules_changed_to_review": sorted(changed),
        "present_requires": "authenticated matching full-write snapshot, namespace/path, fresh call ticket",
        "untrusted_completion_or_partial_write": "unknown/review, never a clean revision",
    }
