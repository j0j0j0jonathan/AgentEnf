"""Inspect retained lookup source and exact recorded inputs; never call models."""

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OLD = Path(
    "/Users/jonathanhofer/Documents/Codex/2026-06-28/i-w/outputs/a3s_enfguard_h_100_20260814"
)
OUT = ROOT / "outputs/paper-improvements-2026-10-14"


def lookup(path):
    text = path.read_text()
    tree = ast.parse(text)
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_pre_evaluated_judge_result"
    )
    body = ast.get_source_segment(text, fn)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "function_line": fn.lineno,
        "single_score_fallback": "len(matches) == 1" in body,
        "function": body,
    }


def main():
    manifest = json.loads(
        (
            ROOT
            / "outputs/paper-preparation-2026-10-14/recorded-replay/recorded-pack/manifest.json"
        ).read_text()
    )
    runs = [r for r in manifest["runs"] if r["cohort"] == "balanced50_on"]
    per = []
    for run in runs:
        contents = {
            e.get("content", "")
            for line in Path(run["predicates"]).read_text().splitlines()
            if (e := json.loads(line)).get("phase") == "outbound"
        }
        per.append(
            {
                "review_id": run["review_id"],
                "inputs": len(contents),
                "nonascii": sum(not s.isascii() for s in contents),
                "source": run["predicates"],
                "sha256": run["predicates_sha256"],
            }
        )
    files = [
        Path(
            "/Users/jonathanhofer/Desktop/BachelorThesis_LLM_Enforcement/code/EnfGuardV2/predicates.py"
        ),
        OLD / "candidates/combined_memory_qwen_v2_superseded_old_base_20260901/predicates.py",
        ROOT / "AgentEnf/predicates.py",
    ]
    report = {
        "lookup_sources": [lookup(p) for p in files],
        "historical_runtime_source_hash_bound": False,
        "conclusion": "Retained Desktop source and archived Sept-1 candidate have the single-score fallback. The retained run manifest hashes the policy and benchmark harness, not this proxy source. These copies do not prove the exact runtime bytes of every thesis run.",
        "outbound_pre_eval_measurement": {
            "unit": "distinct full content within each run, deduplicated across predicate names",
            "runs": len(runs),
            "inputs": sum(r["inputs"] for r in per),
            "nonascii": sum(r["nonascii"] for r in per),
            "runs_with_nonascii": sum(r["nonascii"] > 0 for r in per),
            "rows": per,
        },
        "limits": [
            "Unicode exposure is not a count of incorrect decisions.",
            "A single pre-evaluation for the current reply can reuse the score of the correct original text despite bridge corruption.",
            "The fallback is unsafe for another argument, including a past message. Exact-only lookup under a corrupt bridge can instead reclassify altered text.",
            "The reported 136/166 denominator was not reproduced by this explicitly defined counting method; it may describe a different subset.",
            "Historical benchmark labels remain unchanged; there is no corrected ASR estimate here.",
        ],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "historical-string-audit.json").write_text(json.dumps(report, indent=2) + "\n")
    print({k: v for k, v in report["outbound_pre_eval_measurement"].items() if k != "rows"})


if __name__ == "__main__":
    main()
