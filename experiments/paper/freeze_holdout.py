"""Freeze a seed-disjoint reservation without displaying case contents.

Reads only IDs/categories from dataset objects for selection. Prior exposure is
conservatively inferred from retained filenames, reports, code and result IDs;
this cannot certify the absence of undocumented human/other-agent inspection.
"""

import argparse, collections, hashlib, json, re, secrets, subprocess
from pathlib import Path

ID = re.compile(r"\b(?:syn|seed)-\d{4}\b")
SKIP = {
    "node_modules",
    ".git",
    ".venv",
    "target",
    "_build",
    "__pycache__",
    "toolchain",
    "source-snapshot",
}


def files(root):
    p = subprocess.run(
        [
            "rg",
            "--files",
            "--hidden",
            "-g",
            "!.git",
            "-g",
            "!node_modules",
            "-g",
            "!.venv",
            str(root),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return [Path(s) for s in p.stdout.splitlines() if not SKIP.intersection(Path(s).parts)]


def freeze(dataset, roots, output, size=100):
    if output.exists():
        raise FileExistsError("A frozen reservation must not be overwritten")
    injected = json.loads((dataset / "injected.json").read_text())
    seeds = json.loads((dataset / "seeds.json").read_text())
    seed_index = {r["id"]: r for r in seeds}
    seen = set()
    sources = []
    # Dataset source files and templates are intentionally not treated as prior
    # inspection. Actual retained results/reports/code and selected panels are.
    for root in roots:
        for path in files(root):
            if dataset in path.parents or "skill_templates" in path.parts:
                continue
            hits = set(ID.findall(str(path)))
            if (
                path.suffix in {".py", ".md", ".txt", ".yaml", ".yml", ".csv", ".jsonl"}
                and path.stat().st_size < 5_000_000
            ):
                hits.update(ID.findall(path.read_text(errors="replace")))
            elif path.suffix == ".json" and (
                "selection" in str(path)
                or path.name
                in {
                    "detailed.json",
                    "summary.json",
                    "selection_manifest.json",
                    "case-inventory.json",
                    "manifest.json",
                }
            ):
                # IDs only are retained; no prompt or outcome is displayed.
                hits.update(ID.findall(path.read_text(errors="replace")))
            if hits:
                seen.update(hits)
                sources.append({"path": str(path), "ids": sorted(hits)})
    exposed_seeds = {r["seed_id"] for r in injected if r["id"] in seen} | {
        s for s in seen if s.startswith("seed-")
    }
    eligible = [
        r
        for r in injected
        if r["id"] not in seen and r["seed_id"] not in exposed_seeds and r["seed_id"] in seed_index
    ]
    salt = secrets.token_hex(32)

    def rank(row):
        return hashlib.sha256((salt + row["id"]).encode()).hexdigest()

    by = collections.defaultdict(list)
    for row in sorted(eligible, key=rank):
        by[row["risk_category"]].append(row)
    chosen = []
    used = set()
    while len(chosen) < size:
        advanced = False
        for category in sorted(by):
            while by[category] and by[category][0]["seed_id"] in used:
                by[category].pop(0)
            if by[category] and len(chosen) < size:
                row = by[category].pop(0)
                chosen.append(row)
                used.add(row["seed_id"])
                advanced = True
        if not advanced:
            break
    output.mkdir(parents=True)
    from datetime import datetime, timezone

    entries = [
        {
            "id": r["id"],
            "seed_id": r["seed_id"],
            "risk_category": r["risk_category"],
            "attack_sha256": hashlib.sha256(
                json.dumps(r, sort_keys=True, ensure_ascii=True).encode()
            ).hexdigest(),
            "benign_sha256": hashlib.sha256(
                json.dumps(seed_index[r["seed_id"]], sort_keys=True, ensure_ascii=True).encode()
            ).hexdigest(),
        }
        for r in chosen
    ]
    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "reserved_prior_exposure_not_independently_certified"
        if chosen
        else "no_eligible_seed_disjoint_cases",
        "selection": "round-robin risk categories, salted SHA256 order, one attack per seed, exclude observed attacks and their seed families",
        "salt": salt,
        "requested_pairs": size,
        "reserved_pairs": len(entries),
        "eligible_attacks": len(eligible),
        "eligible_seed_groups": len({r["seed_id"] for r in eligible}),
        "exposed_ids": len(seen),
        "limits": [
            "No case contents displayed during selection.",
            "Local records cannot prove absence of undocumented earlier exposure.",
            "Do not tune on reserved contents; quarantine any subsequently discovered exposure.",
            "If insufficient independent seed groups remain, use a new external dataset or independently commissioned attacks.",
        ],
        "dataset_sha256": {
            n: hashlib.sha256((dataset / n).read_bytes()).hexdigest()
            for n in ("injected.json", "seeds.json")
        },
        "cases": entries,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "exposure-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    # Seal complete selected records for eventual execution. Do not open for tuning.
    (output / "reserved-cases.json").write_text(
        json.dumps(
            {"attacks": chosen, "benign": [seed_index[r["seed_id"]] for r in chosen]},
            ensure_ascii=False,
        )
        + "\n"
    )
    digest = hashlib.sha256((output / "manifest.json").read_bytes()).hexdigest()
    (output / "manifest.sha256").write_text(digest + "  manifest.json\n")
    print(
        json.dumps(
            {
                k: manifest[k]
                for k in (
                    "status",
                    "reserved_pairs",
                    "eligible_attacks",
                    "eligible_seed_groups",
                    "exposed_ids",
                )
            }
        )
    )
    print("Manifest SHA256:", digest)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", type=Path, required=True)
    p.add_argument("--root", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--size", type=int, default=100)
    a = p.parse_args()
    freeze(a.dataset, a.root, a.output, a.size)
