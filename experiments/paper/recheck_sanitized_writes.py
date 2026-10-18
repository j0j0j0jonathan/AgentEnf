"""Targeted current mapper replay; facts only, no tools/models or new ASR."""

import hashlib
import json
from pathlib import Path
from instrlib.tool_mapper import map_tool_call, session_context, reset_authored_content_accumulation
from instrlib.artifact_evidence import facts

ROOT = Path(__file__).resolve().parents[3]
AUDIT = ROOT / "outputs/paper-preparation-2026-10-14"
OUT = ROOT / "outputs/paper-improvements-2026-10-14"


def main():
    rows = [
        r
        for r in json.loads((AUDIT / "block-review.later-panel.json").read_text())["rows"]
        if r["assessment"] == "stale_or_overbroad_fact"
    ]
    report = []
    for row in rows:
        path = Path(row["trace_source"])
        reset_authored_content_accumulation()
        selected = []
        dossier = json.loads((AUDIT / "block-dossiers" / row["dossier"]).read_text())
        full = {}
        for turn in dossier["turns"]:
            for log in turn.get("new_logs", []):
                if log.get("phase") == "start" and isinstance(log.get("args"), dict):
                    key = log.get("tool_call_id")
                    full.setdefault(key, {})[json.dumps(log["args"], sort_keys=True)] = log["args"]
        with session_context("isolated-" + row["review_id"], verified_artifacts=True):
            for line in path.read_text().splitlines():
                batch = json.loads(line)
                for side in ("inbound", "outbound"):
                    for event in batch.get(side, []):
                        if event["name"] != "ToolPlanned":
                            continue
                        tid, call, tool, raw = event["args"]
                        try:
                            args = json.loads(raw)
                        except (ValueError, TypeError):
                            candidates = full.get(call, {})
                            if len(candidates) != 1:
                                continue
                            args = next(iter(candidates.values()))
                        mapped = map_tool_call(tid, call, tool, args)
                        if tid == row["tid"]:
                            selected.append(
                                {
                                    "call_id": call,
                                    "current_facts": sorted(facts(mapped)),
                                    "authored_exfil": ("exfil_kind", "authored_exfil")
                                    in facts(mapped),
                                }
                            )
                if batch["tid"] == row["tid"]:
                    break
        report.append(
            {
                "review_id": row["review_id"],
                "id": row["id"],
                "run": row["run"],
                "tid": row["tid"],
                "source": str(path),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "calls": selected,
            }
        )
    (OUT / "sanitized-write-recheck.json").write_text(
        json.dumps(
            {
                "scope": "deterministic current mapper; classifiers disabled; no execution or policy verdict claim",
                "rows": report,
            },
            indent=2,
        )
        + "\n"
    )
    print(
        [
            (r["id"], r["run"], len(r["calls"]), [c["authored_exfil"] for c in r["calls"]])
            for r in report
        ]
    )


if __name__ == "__main__":
    main()
