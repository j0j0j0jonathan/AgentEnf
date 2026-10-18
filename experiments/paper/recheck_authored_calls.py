"""Replay development write evidence without executing tools or querying models."""
import argparse
import hashlib
import json
from pathlib import Path

from instrlib import tool_mapper as mapper
from instrlib.artifact_evidence import facts
from instrlib.path_confinement import workspace_context


def write_inputs(dossier):
    starts = {}
    for turn in dossier["turns"]:
        for log in turn.get("new_logs", []):
            if log.get("phase") == "start" and isinstance(log.get("args"), dict):
                starts.setdefault(log.get("tool_call_id"), {})[
                    json.dumps(log["args"], sort_keys=True)] = log["args"]
    for batch in dossier["target_batches"]:
        for event in batch.get("inbound", []):
            if event["name"] != "ToolPlanned":
                continue
            tid, call, tool, raw = event["args"]
            try:
                args = json.loads(raw)
                source = "exact_event_arguments"
            except (ValueError, TypeError):
                values = starts.get(call, {})
                if len(values) != 1:
                    raise ValueError("Missing/ambiguous full arguments; cannot replay " + call)
                args = next(iter(values.values()))
                source = "unique_full_tool_start_same_call_id"
            if tool != "file_write" or not isinstance(args.get("content"), str):
                raise ValueError("This review requires a full file write")
            yield tid, call, tool, args, source


def recheck(audit, review_ids, output):
    rows = []
    for review_id in review_ids:
        path = Path(audit) / "block-dossiers" / (review_id + ".json")
        dossier = json.loads(path.read_text())
        roots = sorted({e["args"][3] for b in dossier["target_batches"]
                        for e in b.get("inbound", []) if e["name"] == "Classify"
                        and e["args"][2] == "workspace_root"})
        for tid, call, tool, args, source in write_inputs(dossier):
            invoked = []
            def unavailable(name):
                def record(content):
                    invoked.append({"adapter": name, "input_sha256": hashlib.sha256(content.encode()).hexdigest()})
                    return None, "failed_open"
                return record
            mapper.register_content_disclosure_classifier(unavailable("content_disclosure"))
            mapper.register_authored_capability_classifier(unavailable("authored_capability"))
            mapper.reset_authored_content_accumulation()
            try:
                with workspace_context(roots), mapper.session_context(review_id, verified_artifacts=True):
                    mapped = mapper.map_tool_call(tid, call, tool, args)
            finally:
                mapper.register_content_disclosure_classifier(None)
                mapper.register_authored_capability_classifier(None)
                mapper.reset_authored_content_accumulation()
            rows.append({"review_id": review_id, "source": str(path.resolve()),
                         "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                         "tid": tid, "call_id": call, "argument_source": source,
                         "recorded_workspace_roots": roots,
                         "arguments": args, "current_facts": sorted(facts(mapped)),
                         "classifier_routes": invoked,
                         "deterministic_secret": mapper.contains_secret_material(args["content"]),
                         "scope": "current write only; classifiers explicitly unavailable; no live verdict or ASR claim"})
    Path(output).write_text(json.dumps({"rows": rows}, ensure_ascii=False, indent=2) + "\n")
    return rows


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--audit", type=Path, required=True)
    p.add_argument("--review-id", action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    rows = recheck(a.audit, a.review_id, a.output)
    print(json.dumps([{k: r[k] for k in ("review_id", "tid", "deterministic_secret", "classifier_routes")}
                      for r in rows], indent=2))
