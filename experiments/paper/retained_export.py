"""Verify full-evidence export on retained trajectories without judging outcomes."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from experiments.paper.evidence_bundle import build, normalized_turns


def export(ledger, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    docs, index = {}, []
    totals = Counter()
    for row in json.loads(Path(ledger).read_text()):
        if row["cohort"] not in {"diagnostic100_on", "balanced50_on"}:
            continue
        path = Path(row["source"]) / "detailed.json"
        if path not in docs:
            raw = path.read_bytes()
            docs[path] = (json.loads(raw), hashlib.sha256(raw).hexdigest())
        doc, source_hash = docs[path]
        results = [r for r in doc["results"] if r["item"]["id"] == row["id"]]
        if len(results) != 1:
            raise ValueError("Ambiguous item selection")
        candidates = results[0]["all_runs"]
        if row["cohort"] == "balanced50_on":
            if len(candidates) != 1:
                raise ValueError("Later run directory must contain exactly one repetition")
        else:
            candidates = [r for r in candidates if r["run_index"] == row["run"] - 1]
        if len(candidates) != 1:
            raise ValueError("Ambiguous repetition selection")
        run = candidates[0]
        identity = hashlib.sha256(json.dumps([row["cohort"], row["id"], row["run"]]).encode()).hexdigest()[:24]
        contract = {"id": "export-coverage-only", "effects": [{"id": "not-adjudicated"}],
                    "scope": "Format/coverage check only. No outcome judgment is authorized by this placeholder."}
        bundle = build(run, contract, run_id=identity)
        turns = normalized_turns(run)
        # Compare original full fields with exported fields, never previews.
        logs = [log for turn in turns for log in turn["logs"]]
        exported = [r["payload"] for r in bundle["evidence"] if r["kind"] == "runtime_log"]
        if len(logs) != len(exported):
            raise AssertionError("Tool records dropped")
        for before, after in zip(logs, exported):
            for key in ("args", "result", "error", "tool_call_id", "phase", "tool_name"):
                if (key in before) != (key in after) or before.get(key) != after.get(key):
                    raise AssertionError("Original tool evidence changed")
        for kind, key in (("user_message", "user"), ("recorded_agent_reply", "agent")):
            assert [r["payload"] for r in bundle["evidence"] if r["kind"] == kind] == [t[key] for t in turns]
        raw = (json.dumps(bundle, ensure_ascii=False) + "\n").encode()
        (destination / (identity + ".json")).write_bytes(raw)
        for key in ("turns", "complete_tool_logs", "starts", "results", "other", "evidence_utf8_bytes"):
            totals[key] += bundle["coverage"][key]
        totals["runs"] += 1
        totals["exact_field_checks_passed"] += 1
        index.append({"bundle": identity + ".json", "bundle_sha256": hashlib.sha256(raw).hexdigest(),
                      "cohort": row["cohort"], "case": row["id"], "run": row["run"],
                      "source": str(path), "source_sha256": source_hash,
                      "gap_count": len(bundle["gaps"])})
    summary = {"status": "export_verified_not_judged", "totals": dict(totals),
               "source_ledger_sha256": hashlib.sha256(Path(ledger).read_bytes()).hexdigest(),
               "new_model_calls": 0, "holdout": False,
               "limitations": ["Historical capture gaps are not repaired by exporting.",
                               "Contracts are coverage placeholders, not outcome-label definitions.",
                               "No historical labels or benchmark-twin transcript is in the bundles."],
               "index": index}
    (destination / "index.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ledger", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    print(json.dumps(export(a.ledger, a.destination)["totals"], indent=2))
