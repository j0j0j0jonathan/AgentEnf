"""Replay recorded quote scores with explicit permission facts; no API calls.

Keeps the failed experiment unchanged. This is a development candidate check,
not an end-to-end run, and does not install the new gate in the serving proxy.
"""
import argparse
from collections import Counter
import json
from pathlib import Path

from experiments.paper import calibrate_reply_quotes as quotes
from experiments.paper import reply_quote_witness as witness
from experiments.paper.calibrate import dump, sha
from instrlib import permission_effects


def combine(evidence, full_scores, unit_scores):
    base = witness.combine(evidence, full_scores, unit_scores)  # Validate every recorded probability first.
    reply = json.loads(evidence)["reply"]
    units = witness.code_units(reply)
    if len(units) != len(unit_scores):
        raise ValueError("Every unit requires its recorded classifier answer")
    facts = [permission_effects.chmod_system_worldwrite(unit) for unit in units]
    # The structural fact raises evidence; it does not directly bypass refusal,
    # novelty, or the witness check. A previously supplied quote may still Allow.
    raised = [1.0 if found else score for found, score in zip(facts, unit_scores, strict=True)]
    result = witness.combine(evidence, full_scores, raised)
    result["previous_label"] = base["label"]
    result["recorded_quoted_payload_scores"] = unit_scores
    result["permission_facts_by_unit"] = facts
    return result


def replay(previous, output):
    previous, output = Path(previous).resolve(), Path(output).resolve()
    quotes.check(previous)
    recorded_summary = json.loads((previous / "combined-summary.json").read_text())
    if quotes.summarize(previous) != recorded_summary:
        raise ValueError("Previous results inconsistent")
    if recorded_summary["unit_summary"]["pending"] or recorded_summary["error_unit_ids"]:
        raise ValueError("Previous experiment incomplete")
    cases = json.loads((previous / "original-cases.json").read_text())["cases"]
    full = {row["id"]: row for row in json.loads((previous / "recorded-scores.json").read_text())["decisions"]}
    units = {row["id"]: row for row in json.loads((previous / "units/cases.json").read_text())["cases"]}
    answers = {row["id"]: row for row in map(json.loads, (previous / "units/results.jsonl").read_text().splitlines())}
    combined = []
    for case in cases:
        code = witness.code_units(json.loads(case["input"])["reply"])
        scores = [answers[quotes.unit_id(unit)]["probability"] for unit in code]
        result = combine(case["input"], full[case["id"]]["component_scores"], scores)
        combined.append({"id": case["id"], "expected": case["expected"], **result})
    property_rows = []
    for ident, case in units.items():
        code = json.loads(case["input"])["reply"]
        facts = permission_effects.chmod_system_worldwrite(code)
        answer = answers[ident]
        property_rows.append({"id": ident, "expected": case["expected"],
                              "classifier_probability": answer["probability"],
                              "permission_facts": facts,
                              "label": int(bool(facts) or answer["probability"] >= .5)})
    count = lambda rows: dict(Counter("agree" if row["label"] == row["expected"] else "disagree" for row in rows))
    sources = [Path(__file__), Path(permission_effects.__file__), Path(witness.__file__)]
    report = {"replay_counts": count(combined), "property_counts": count(property_rows),
              "decisions": combined, "property_results": property_rows,
              "source_hashes": {str(path): sha(path) for path in sources},
              "source_results_sha256": sha(previous / "units/results.jsonl"),
              "source_summary_sha256": sha(previous / "combined-summary.json"),
              "api_calls": 0, "runtime_integrated": False,
              "claim": "Deterministic addition to recorded classifier answers; selected development replay only"}
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "summary.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = replay(args.previous, args.output)
    print(json.dumps({k: v for k, v in result.items() if k not in {"decisions", "property_results"}}, indent=2))
