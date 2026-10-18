"""Frozen multi-classifier development smoke check. Preparation never calls APIs.

Expected labels are predeclared review judgments, never sent to a classifier.
Uses production predicate/ingest adapters; an error is not a negative answer.
"""
import argparse
from collections import Counter
import getpass
import hashlib
import json
import os
from pathlib import Path
import time

import yaml
from experiments.paper.calibrate import dump, sha

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ["predicates.py", "instrlib/tool_judge.py", "instrlib/decisions.py",
           "instrlib/evidence_budget.py", "instrlib/judge_capture.py",
           "instrlib/reply_evidence.py", "mappings.py", "batch_judge.py",
           "proxy.py", "event_schema.py", "enfguard.sig", "yaml_loader.py", "static_analysis.py",
           "experiments/release_candidate/evidence_contracts.py",
           "experiments/paper/calibrate.py", "experiments/paper/calibrate_semantics.py"]
ROUTED = {
    "content_disclosure": ("_CONTENT_DISCLOSURE_SYSTEM_PROMPT", "classify_content_disclosure_with_status"),
    "authored_capability": ("_AUTHORED_CAPABILITY_SYSTEM_PROMPT", "classify_authored_capability_with_status"),
}


def prepare(cases_path, profile, output, model="gpt-6-luna", *, criterion_overrides=None):
    from instrlib import tool_judge
    cases = json.loads(Path(cases_path).read_text())["cases"]
    if not cases or len({c["id"] for c in cases}) != len(cases):
        raise ValueError("Unique, nonempty case IDs required")
    predicates = {p["name"]: p["system_prompt"] for p in yaml.safe_load(Path(profile).read_text())["predicates"]
                  if p.get("kind") == "llm_judge"}
    targets = {}
    for c in cases:
        target = c["target"]
        if not isinstance(c["input"], str):
            raise ValueError("Exact string input required")
        if target in ROUTED:
            labels = {"benign", "authored_exfil", "deferred_capability"} if target == "authored_capability" else {"benign", "secret_material", "system_prompt"}
            targets[target] = {"kind": "routed", "criterion": getattr(tool_judge, ROUTED[target][0])}
        elif target in predicates:
            labels = {0, 1}
            targets[target] = {"kind": "predicate", "criterion": predicates[target]}
        else:
            raise ValueError("Unknown target: " + target)
        if c.get("expected") is not None and c["expected"] not in labels:
            raise ValueError("Invalid expected label")
    overrides = criterion_overrides or {}
    if set(overrides) - set(targets):
        raise ValueError("Override names a target absent from these cases")
    for target, criterion in overrides.items():
        if not isinstance(criterion, str) or not criterion.strip():
            raise ValueError("Override must be a nonempty criterion")
        targets[target].update(criterion=criterion, criterion_origin="experimental_override")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    dump(output / "cases.json", {"cases": cases})
    dump(output / "targets.json", targets)
    manifest = {"purpose": "development smoke check; preliminary labels, not accuracy estimate",
                "model": model, "backend": "openai_decisions", "timeout_seconds": 150,
                "criterion_overrides": sorted(overrides),
                "budget_bytes": 65536, "repetitions": 1, "planned": len(cases),
                "source_hashes": {p: sha(ROOT / p) for p in SOURCES},
                "cases_sha256": sha(output / "cases.json"),
                "targets_sha256": sha(output / "targets.json"), "profile_sha256": sha(profile)}
    dump(output / "manifest.json", manifest)
    return manifest


def check(output):
    output = Path(output)
    m = json.loads((output / "manifest.json").read_text())
    for file in ("cases", "targets"):
        if sha(output / (file + ".json")) != m[file + "_sha256"]:
            raise ValueError("Frozen " + file + " changed")
    for file, expected in m["source_hashes"].items():
        if sha(ROOT / file) != expected:
            raise ValueError("Runtime changed; prepare a new calibration: " + file)
    return m


def classify(target, spec, content, model, timeout, index):
    if spec["kind"] == "predicate":
        from predicates import _call_and_parse_judge_api
        answer = _call_and_parse_judge_api(spec["criterion"], content,
                  backend="openai_decisions", model=model, timeout_ms=int(timeout * 1000))
        if answer.fail_mode:
            raise ValueError("Failed predicate result")
        return {"status": "ok", "label": int(answer.raw_score >= .5),
                "probability": answer.raw_score, "raw_reply": answer.raw_reply}
    from instrlib import tool_judge, judge_capture
    # Include the per-adapter override so ambient demo settings cannot change it.
    os.environ.update(ENFGUARD_TOOL_JUDGE="1", ENFGUARD_TOOL_JUDGE_BACKEND="openai_decisions",
                      ENFGUARD_TOOL_JUDGE_TIMEOUT=str(timeout))
    os.environ["ENFGUARD_TOOL_JUDGE_MODEL_" + target.upper()] = model
    # This runner is a serial, separate experiment process. Temporarily bind
    # its frozen criterion while retaining the actual production parser and
    # transport. Never use this override mechanism inside a serving proxy.
    prompt_name, function_name = ROUTED[target]
    original_prompt = getattr(tool_judge, prompt_name)
    try:
        setattr(tool_judge, prompt_name, spec.get("criterion", original_prompt))
        with judge_capture.capturing(index):
            label, status = getattr(tool_judge, function_name)(content)
    finally:
        setattr(tool_judge, prompt_name, original_prompt)
    captures = judge_capture.pop_judge_calls(index)
    # Error strings can contain HTTP details; retain only the status and successful reply.
    safe = [{k: c[k] for k in ("adapter", "prompt_sha8", "ms") if k in c}
            | {"error": bool(c.get("error")), "raw_reply": c["reply"] if not c.get("error") else None}
            for c in captures]
    if status not in {"classified", "no_match"}:
        return {"status": "error", "label": None, "adapter_status": status, "calls": safe}
    return {"status": "ok", "label": label or "benign", "adapter_status": status, "calls": safe}


def summarize(cases, results):
    expected = {c["id"]: c for c in cases}
    counts, targets = Counter(), {}
    for r in results:
        c = expected[r["id"]]
        key = "error" if r["status"] != "ok" else (
            "unadjudicated" if c["expected"] is None else (
                "agree" if r["label"] == c["expected"] else "disagree"))
        counts[key] += 1
        targets.setdefault(c["target"], Counter())[key] += 1
    return {"planned": len(cases), "attempted": len(results), "pending": len(cases)-len(results),
            "counts": dict(counts), "by_target": {k: dict(v) for k, v in targets.items()},
            "claim": "development agreement with preliminary labels only"}


def run(output, call=classify):
    output = Path(output)
    m = check(output)
    os.environ.update(ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES=str(m["budget_bytes"]),
                      ENFGUARD_DECISIONS_BASE_URL="https://api.openai.com")
    cases = json.loads((output / "cases.json").read_text())["cases"]
    targets = json.loads((output / "targets.json").read_text())
    journal = output / "results.jsonl"
    results = [json.loads(s) for s in journal.read_text().splitlines()] if journal.exists() else []
    ids = [r["id"] for r in results]
    if len(ids) != len(set(ids)) or not set(ids) <= {c["id"] for c in cases}:
        raise ValueError("Duplicate or foreign results")
    marker = output / "attempt-in-progress.json"
    if marker.exists():
        if json.loads(marker.read_text())["id"] not in ids:
            raise ValueError("Interrupted request may have been billed; inspect before retrying")
        marker.unlink()
    for i, c in enumerate(cases):
        if c["id"] in ids:
            continue  # No automatic retries, even on an earlier error.
        row = {"id": c["id"], "target": c["target"],
               "input_sha256": hashlib.sha256(c["input"].encode()).hexdigest()}
        dump(marker, row)
        started = time.monotonic()
        try:
            row.update(call(c["target"], targets[c["target"]], c["input"],
                            m["model"], m["timeout_seconds"], i + 1))
        except Exception as exc:
            row.update(status="error", error_type=type(exc).__name__, label=None)
        row["seconds"] = time.monotonic() - started
        with journal.open("a") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush(); os.fsync(handle.fileno())
        results.append(row)
        marker.unlink()
        dump(output / "summary.json", summarize(cases, results))
        print(f"{len(results)}/{len(cases)} {c['target']}: {row['status']}", flush=True)
        if row["status"] != "ok":
            break
    return summarize(cases, results)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    prep = sub.add_parser("prepare")
    for name in ("cases", "profile", "output"):
        prep.add_argument("--" + name, type=Path, required=True)
    prep.add_argument("--model", required=True)
    for name in ("check", "run"):
        sub.add_parser(name).add_argument("directory", type=Path)
    a = p.parse_args()
    os.umask(0o077)
    if a.operation == "prepare":
        print(prepare(a.cases, a.profile, a.output, a.model)); return
    m = check(a.directory)
    if a.operation == "check":
        print(f"Verified {m['planned']} inputs; no API calls."); return
    key = os.environ.get("OPENAI_API_KEY") or os.environ.get("JUDGE_OPENAI_API_KEY")
    if not key:
        key = getpass.getpass("OpenAI API key (hidden): ").strip()
    if not key:
        raise SystemExit("No key supplied; no calls made.")
    os.environ.update(JUDGE_OPENAI_API_KEY=key, ENFGUARD_TOOL_JUDGE_OPENAI_API_KEY=key,
                      ENFGUARD_STATE_DIR=str(a.directory / "state"),
                      ENFGUARD_LOG_DIR=str(a.directory / "logs"))
    result = run(a.directory)
    print(json.dumps(result, indent=2))
    if result["pending"] or result["counts"].get("error") or result["counts"].get("disagree"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
