"""Frozen development calibration through the actual predicate transport/parser.

Preparation and checks are offline. --run is explicit and accepts a key only
from the environment or a hidden terminal prompt. No labels go to the model.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import getpass
import hashlib
import json
import math
import os
from pathlib import Path
import time

import yaml

ROOT = Path(__file__).resolve().parents[2]
PREDICATE = "operationalizes_untrusted_harm"
SOURCES = ["predicates.py", "instrlib/decisions.py", "instrlib/evidence_budget.py",
           "experiments/paper/calibrate.py"]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def prepare(cases_path, profile_path, destination, model, *, threshold=.5, timeout=150):
    if not model or not math.isfinite(threshold) or not 0 < threshold < 1 or timeout <= 0:
        raise ValueError("Explicit model, valid threshold and timeout required")
    doc = json.loads(Path(cases_path).read_text())
    rows = doc["cases"]
    if not rows or len({r["id"] for r in rows}) != len(rows):
        raise ValueError("Nonempty unique case IDs required")
    for row in rows:
        if not isinstance(row.get("input"), str) or row.get("expected") not in {None, 0, 1}:
            raise ValueError("Invalid calibration row")
    profile = yaml.safe_load(Path(profile_path).read_text())
    matches = [p for p in profile["predicates"] if p["name"] == PREDICATE]
    if len(matches) != 1:
        raise ValueError("Exactly one target predicate required")
    prompt = matches[0]["system_prompt"]
    if doc["contract_sha256"] != hashlib.sha256(prompt.encode()).hexdigest():
        raise ValueError("Calibration labels and selected output contract differ")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    dump(destination / "cases.json", doc)
    (destination / "criterion.txt").write_text(prompt)
    manifest = {
        "schema": 1, "created_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "development contract calibration, not held-out accuracy",
        "predicate": PREDICATE, "backend": "openai_decisions", "model": model,
        "threshold": threshold, "comparison": ">=", "timeout_seconds": timeout,
        "input_budget_bytes": 65536, "failure_posture": "closed",
        "endpoint_base": "https://api.openai.com",
        "planned_inputs": len(rows), "repetitions": 1,
        "labels": "preliminary assistant labels; independent adjudication pending",
        "case_sha256": sha(destination / "cases.json"),
        "criterion_sha256": sha(destination / "criterion.txt"),
        "profile_sha256": sha(profile_path),
        "source_hashes": {name: sha(ROOT / name) for name in SOURCES},
        "sent_to_model": "exact input and criterion only; no expected label, source or rationale",
    }
    dump(destination / "manifest.json", manifest)
    return manifest


def check(directory):
    directory = Path(directory)
    m = json.loads((directory / "manifest.json").read_text())
    if sha(directory / "cases.json") != m["case_sha256"] or sha(directory / "criterion.txt") != m["criterion_sha256"]:
        raise ValueError("Frozen cases or criterion changed; prepare a new calibration")
    for file, expected in m["source_hashes"].items():
        if sha(ROOT / file) != expected:
            raise ValueError("Calibration runtime changed: " + file)
    return m


def summarize(cases, results):
    expected = {c["id"]: c["expected"] for c in cases}
    counts = Counter()
    for r in results:
        if r["status"] != "ok":
            counts["errors"] += 1
        elif expected[r["id"]] is None:
            counts["unadjudicated"] += 1
        else:
            counts["scored"] += 1
            counts[("true_positive" if r["label"] else "false_negative") if expected[r["id"]]
                   else ("false_positive" if r["label"] else "true_negative")] += 1
    return {"counts": dict(counts), "planned": len(cases), "attempted": len(results),
            "pending": len(cases) - len(results), "errors_counted_as_negative": False,
            "accuracy_claim": "development agreement with preliminary labels only"}


def run(directory, *, call=None):
    directory = Path(directory)
    m = check(directory)
    os.environ["ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES"] = str(m["input_budget_bytes"])
    os.environ["ENFGUARD_DECISIONS_BASE_URL"] = m["endpoint_base"]
    cases = json.loads((directory / "cases.json").read_text())["cases"]
    criterion = (directory / "criterion.txt").read_text()
    journal = directory / "results.jsonl"
    results = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
    ids = [r["id"] for r in results]
    if len(set(ids)) != len(ids) or not set(ids) <= {c["id"] for c in cases}:
        raise ValueError("Duplicate or foreign result IDs")
    started_file = directory / "attempt-in-progress.json"
    if started_file.exists():
        started_id = json.loads(started_file.read_text())["id"]
        if started_id not in ids:
            raise ValueError("An interrupted request may have been billed; inspect before retrying")
        started_file.unlink()
    # A persisted attempt is never silently retried. Inspect failures and prepare
    # a separately named experiment if a retry is needed.
    if call is None:
        from predicates import _call_and_parse_judge_api
        call = _call_and_parse_judge_api
    for c in cases:
        if c["id"] in ids:
            continue
        started = time.monotonic()
        r = {"id": c["id"], "input_sha256": hashlib.sha256(c["input"].encode()).hexdigest()}
        dump(started_file, r)
        try:
            answer = call(criterion, c["input"], backend=m["backend"], model=m["model"],
                          timeout_ms=int(m["timeout_seconds"] * 1000))
            if answer.fail_mode:
                raise ValueError("Classifier reported a failed result")
            r.update(status="ok", probability=answer.raw_score,
                     label=int(answer.raw_score >= m["threshold"]), raw_reply=answer.raw_reply)
        except Exception as exc:
            # Exception text may include request bodies or auth information.
            # Keep the class/status and a specific budget reason, never headers.
            from instrlib.evidence_budget import EvidenceBudgetExceeded
            r.update(status="error", error_type=type(exc).__name__, label=None,
                     runtime_failure_response="block", probability=None)
            if isinstance(exc, EvidenceBudgetExceeded):
                r["reason"] = str(exc)
            response = getattr(exc, "response", None)
            if response is not None:
                r["http_status"] = response.status_code
        r["elapsed_seconds"] = time.monotonic() - started
        with journal.open("a") as handle:
            handle.write(json.dumps(r, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        results.append(r)
        started_file.unlink()
        dump(directory / "summary.json", summarize(cases, results))
        print(f"{len(results)}/{len(cases)} {c['id']}: {r['status']}", flush=True)
        if r["status"] == "error":
            # Stop on auth/rate-limit/transport failure instead of spending the
            # remaining budget on repeated failures; unknown stays visible.
            break
    summary = summarize(cases, results)
    dump(directory / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--cases", required=True, type=Path)
    p.add_argument("--profile", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--model", required=True)
    for name in ("check", "run"):
        p = sub.add_parser(name)
        p.add_argument("directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "prepare":
        m = prepare(args.cases, args.profile, args.output, args.model)
        print(f"Prepared {m['planned_inputs']} inputs; no API calls.")
    else:
        m = check(args.directory)
        if args.operation == "check":
            print(f"Verified {m['planned_inputs']} inputs and source hashes; no API calls.")
            return
        key = os.environ.get("JUDGE_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not key:
            key = getpass.getpass("OpenAI API key (hidden): ").strip()
        if not key:
            raise SystemExit("No key supplied; no calls made.")
        os.environ["JUDGE_OPENAI_API_KEY"] = key
        # Keep imported predicate state isolated from the working demo.
        os.environ["ENFGUARD_STATE_DIR"] = str(args.directory / "state")
        os.environ["ENFGUARD_LOG_DIR"] = str(args.directory / "logs")
        summary = run(args.directory)
        print(json.dumps(summary, indent=2))
        if summary["pending"] or summary["counts"].get("errors"):
            raise SystemExit(2)


if __name__ == "__main__":
    main()
