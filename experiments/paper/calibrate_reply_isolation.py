"""Isolate reply properties from history without changing criteria or labels.

Development diagnostic only, not connected to the proxy. Two separately
journalled Decisions requests per case: reply-only payload/refusal questions,
then a coverage question on the unchanged full evidence. Repeated identical
replies are intentionally sampled again to expose variability; no cache hides it.
"""
import argparse
from collections import Counter
import getpass
import hashlib
import json
import os
from pathlib import Path
import shlex

from experiments.paper import calibrate_reply_components as components
from experiments.paper import calibrate_semantics as calibration
from experiments.paper.calibrate import dump, sha
from instrlib.reply_evidence import reply_from_evidence

STAGES = {
    "reply-only": ("dangerous_payload_present", "refusal_only"),
    "coverage-only": ("prior_coverage",),
}
TARGET = "operationalizes_untrusted_harm"


def classify(target, spec, content, model, timeout, index):
    del target, index
    from instrlib import decisions
    criteria = json.loads(spec["criterion"])
    if tuple(criteria) not in STAGES.values():
        raise ValueError("Unknown isolation stage")
    if criteria != {name: components.CRITERIA[name] for name in criteria}:
        raise ValueError("This diagnostic must keep the prior criteria")
    payload = json.loads(content)
    if tuple(criteria) == STAGES["reply-only"]:
        if set(payload) != {"reply"} or not isinstance(payload["reply"], str):
            raise ValueError("Reply-only stage must not receive history")
    else:
        reply_from_evidence(content)
    questions = [decisions.predicate_question(name, criterion) for name, criterion in criteria.items()]
    data = decisions.ask(content, questions, timeout, model=model)
    answers = decisions.validate(data, questions)
    scores = {answer["name"]: answer["probability"] for answer in answers}
    bits = {name: score >= components.THRESHOLD for name, score in scores.items()}
    # The shared runner's stage summary describes the first property. The final
    # report below checks every component and the original policy decision.
    return {"status": "ok", "label": int(bits[next(iter(criteria))]),
            "component_scores": scores, "components": bits,
            "raw_reply": json.dumps(data, ensure_ascii=False)}


def verify_source(previous):
    previous = Path(previous)
    manifest = calibration.check(previous)
    experiment = json.loads((previous / "experiment.json").read_text())
    if sha(components.__file__) != experiment["driver_sha256"]:
        raise ValueError("Prior component driver changed")
    if sha(calibration.ROOT / "examples/presets/release-candidate.yaml") != manifest["profile_sha256"]:
        raise ValueError("Prior candidate profile changed")
    cases = json.loads((previous / "cases.json").read_text())["cases"]
    results = [json.loads(line) for line in (previous / "results.jsonl").read_text().splitlines()]
    if len(results) != len(cases) or {r["id"] for r in results} != {c["id"] for c in cases}:
        raise ValueError("Prior results incomplete or duplicated")
    case_map = {case["id"]: case for case in cases}
    for result in results:
        case = case_map[result["id"]]
        if result["status"] != "ok" or result["input_sha256"] != hashlib.sha256(case["input"].encode()).hexdigest():
            raise ValueError("Prior result failed or has wrong input")
    return cases, manifest


def prepare(previous, output):
    previous, output = Path(previous).resolve(), Path(output).resolve()
    cases, source_manifest = verify_source(previous)
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "original-cases.json", {"cases": cases})
    for stage, names in STAGES.items():
        rows = []
        for case in cases:
            reply = reply_from_evidence(case["input"])
            text = json.dumps({"reply": reply}, ensure_ascii=True, separators=(",", ":")) if stage == "reply-only" else case["input"]
            rows.append({**case, "input": text,
                         "expected": case["expected_components"][names[0]],
                         "expected_final_decision": case["expected"]})
        source = output / (stage + "-inputs.json")
        dump(source, {"cases": rows})
        calibration.prepare(source, calibration.ROOT / "examples/presets/release-candidate.yaml",
            output / stage, model=source_manifest["model"],
            criterion_overrides={TARGET: json.dumps({name: components.CRITERIA[name] for name in names}, ensure_ascii=False)})
    dump(output / "experiment.json", {
        "driver_sha256": sha(__file__), "components_driver_sha256": sha(components.__file__),
        "previous": str(previous), "previous_results_sha256": sha(previous / "results.jsonl"),
        "original_cases_sha256": sha(output / "original-cases.json"),
        "stage_manifest_sha256": {stage: sha(output / stage / "manifest.json") for stage in STAGES},
        "planned_requests": len(cases) * 2, "cases": len(cases),
        "change": "Input/question separation only; same criteria, threshold, model and final labels",
        "threshold": components.THRESHOLD, "runtime_integrated": False,
        "sampling": "one request per stage and case; repeated identical replies deliberately resampled",
        "labels": "predeclared development judgments, not independent gold",
    })
    script = output / "01-check-reply-isolation.command"
    script.write_text("#!/bin/zsh\nset -eu\numask 077\ncd " + shlex.quote(str(calibration.ROOT)) +
        "\nexec " + shlex.quote(str(calibration.ROOT / ".venv/bin/python")) +
        " -m experiments.paper.calibrate_reply_isolation run " + shlex.quote(str(output)) + "\n")
    script.chmod(0o700)
    return output


def check(output):
    output = Path(output)
    experiment = json.loads((output / "experiment.json").read_text())
    expected = [(Path(__file__), experiment["driver_sha256"]),
                (Path(components.__file__), experiment["components_driver_sha256"]),
                (Path(experiment["previous"]) / "results.jsonl", experiment["previous_results_sha256"]),
                (output / "original-cases.json", experiment["original_cases_sha256"])]
    expected += [(output / stage / "manifest.json", digest)
                 for stage, digest in experiment["stage_manifest_sha256"].items()]
    for path, digest in expected:
        if sha(path) != digest:
            raise ValueError("Frozen experiment changed: " + str(path))
    for stage in STAGES:
        manifest = calibration.check(output / stage)
        if sha(calibration.ROOT / "examples/presets/release-candidate.yaml") != manifest["profile_sha256"]:
            raise ValueError("Candidate profile changed")
    return experiment


def summarize(output):
    from instrlib import decisions
    output = Path(output)
    cases = json.loads((output / "original-cases.json").read_text())["cases"]
    by_stage = {}
    for stage in STAGES:
        path = output / stage / "results.jsonl"
        results = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        if len({r["id"] for r in results}) != len(results) or not {r["id"] for r in results} <= {c["id"] for c in cases}:
            raise ValueError("Duplicate or foreign stage results")
        stage_cases = {row["id"]: row for row in json.loads((output / stage / "cases.json").read_text())["cases"]}
        questions = [decisions.predicate_question(name, components.CRITERIA[name]) for name in STAGES[stage]]
        for result in results:
            if result["input_sha256"] != hashlib.sha256(stage_cases[result["id"]]["input"].encode()).hexdigest():
                raise ValueError("Recorded stage input hash mismatch")
            if result["status"] == "ok":
                answers = decisions.validate(json.loads(result["raw_reply"]), questions)
                scores = {answer["name"]: answer["probability"] for answer in answers}
                bits = {name: score >= components.THRESHOLD for name, score in scores.items()}
                if (scores != result["component_scores"] or bits != result["components"]
                        or result["label"] != int(bits[STAGES[stage][0]])):
                    raise ValueError("Recorded stage score mismatch")
        by_stage[stage] = {r["id"]: r for r in results}
    combined, errors, pending = [], [], []
    for case in cases:
        stages = [by_stage[stage].get(case["id"]) for stage in STAGES]
        if any(result is not None and result["status"] != "ok" for result in stages):
            errors.append(case["id"])
        elif any(result is None for result in stages):
            pending.append(case["id"])
        else:
            scores = {name: score for result in stages for name, score in result["component_scores"].items()}
            bits = {name: score >= components.THRESHOLD for name, score in scores.items()}
            combined.append({"id": case["id"], "status": "ok", "component_scores": scores,
                             "components": bits, "label": components.decision(bits),
                             "expected": case["expected"],
                             "seconds_sum": sum(result["seconds"] for result in stages)})
    counts = Counter("agree" if row["label"] == row["expected"] else "disagree" for row in combined)
    report = {"cases": len(cases), "completed_cases": len(combined), "counts": dict(counts),
              "pending_case_ids": pending, "error_case_ids": errors,
              "component_report": components.summarize_components(cases, combined),
              "decisions": combined, "runtime_integrated": False,
              "claim": "Selected development label agreement only; no independent accuracy estimate"}
    dump(output / "combined-summary.json", report)
    return report


def run(output):
    output = Path(output)
    check(output)  # Check both stages before requesting a key or making any call.
    existing = summarize(output)
    if existing["error_case_ids"]:
        raise SystemExit("A recorded request failed; inspect before continuing.")
    if not existing["pending_case_ids"]:
        print("Already complete; no API calls.")
        return existing
    key = os.environ.get("JUDGE_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY") or getpass.getpass("OpenAI API key (hidden): ").strip()
    if not key:
        raise SystemExit("No key supplied; no requests made.")
    os.environ.update(JUDGE_OPENAI_API_KEY=key, ENFGUARD_STATE_DIR=str(output / "state"),
                      ENFGUARD_LOG_DIR=str(output / "logs"))
    for stage in STAGES:
        summary = calibration.run(output / stage, call=classify)
        if summary["pending"] or summary["counts"].get("error"):
            summarize(output)
            raise SystemExit("Incomplete stage; inspect the recorded error before another attempt.")
    report = summarize(output)
    print(json.dumps({k: v for k, v in report.items() if k not in {"decisions", "component_report"}}, indent=2))
    print("Diagnostic only. Inspect component scores and final decisions before any runtime integration.")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--previous", type=Path, required=True)
    prep.add_argument("--output", type=Path, required=True)
    for operation in ("run", "check"):
        sub.add_parser(operation).add_argument("directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "prepare":
        print(prepare(args.previous, args.output))
    elif args.operation == "check":
        print(json.dumps(check(args.directory), indent=2))
    else:
        run(args.directory)
