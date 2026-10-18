"""Reserve IDs only, distinguishing dataset possession from development use.

Consumes the earlier ID-only exposure ledger, plus fresh ledgers of IDs found in
development files. No case text is printed or copied to the reservation. This is
an auditable local-record criterion, not proof of independent human custody.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets


TECHNIQUES = {
    "Fragmented payload assembly": "temporal",
    "Staged multi-step": "temporal",
    "Gradual extraction": "temporal",
    "Multi-turn progressive escalation": "temporal",
    "File-mediated memory poisoning": "spatial",
    "Context-rich request embedding": "semantic",
    "Legitimate-looking change": "semantic",
    "Context manipulation": "semantic",
    "Ambiguous cleanup/persistence instruction": "semantic",
    "Ambiguous cleanup instruction": "semantic",
    "Over-broad permission request": "semantic",
    "Direct request": "direct",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exposure_kind(path):
    """Conservative default: unknown evidence excludes, not includes.

    Selection/config directories are exempt only for data files, never source
    code or analysis prose. Raw run artifacts take precedence over config files.
    """
    p = Path(path)
    parts = {part.lower() for part in p.parts}
    if p.name.startswith("dataset_") and p.suffix in {".json", ".jsonl"}:
        return "dataset_copy"
    if parts & {"raw", "live"} or p.name in {
        "rollout.json", "detailed.json", "scores.json", "enfguard-verdicts.jsonl",
        "benchmark-mock-debug.log", "result.json", "COMPLETE.json",
    }:
        return "run_evidence"
    if parts & {"tests", "analysis", "dossiers", "block-dossiers"}:
        return "substantive_or_unresolved"
    if p.suffix not in {".py", ".md"} and (
        any(x.startswith("selection") for x in parts)
        or "config" in parts or p.suffix in {".yaml", ".yml"}
    ):
        return "selection_or_config"
    return "substantive_or_unresolved"


def pool(attacks, seed_ids, sources):
    excluded = set()
    by_reason = defaultdict(set)
    for source in sources:
        kind = exposure_kind(source["path"])
        by_reason[kind].update(source["ids"])
        if kind in {"run_evidence", "substantive_or_unresolved"}:
            excluded.update(source["ids"])
    direct = [r for r in attacks if r["id"] not in excluded
              and r["seed_id"] not in excluded and r["seed_id"] in seed_ids]
    exposed_families = {r["seed_id"] for r in attacks if r["id"] in excluded}
    eligible = [r for r in direct if r["seed_id"] not in exposed_families]
    return eligible, direct, by_reason, excluded


def select(eligible, size, salt):
    """Balance categories first, then evasion groups within each category.

    Prefer the least represented available stratum; tie-break with a salted hash.
    A seed can occur once. This is stratified coverage, not population sampling.
    """
    remaining = list(eligible)
    chosen, used = [], set()
    categories, strata = Counter(), Counter()
    while len(chosen) < size:
        remaining = [r for r in remaining if r["seed_id"] not in used]
        if not remaining:
            break
        def rank(r):
            category = r["risk_category"]
            return (categories[category], strata[(category, TECHNIQUES[r["technique"]])],
                    digest((salt + r["id"]).encode()))
        row = min(remaining, key=rank)
        chosen.append(row)
        used.add(row["seed_id"])
        categories[row["risk_category"]] += 1
        strata[(row["risk_category"], TECHNIQUES[row["technique"]])] += 1
    if len(chosen) != size:
        raise ValueError(f"Only {len(chosen)} disjoint pairs available; requested {size}")
    return chosen


def reserve(dataset, ledgers, output, size=100, salt=None):
    if output.exists():
        raise FileExistsError("Never overwrite a reservation")
    attacks = json.loads((dataset / "injected.json").read_text())
    seeds = json.loads((dataset / "seeds.json").read_text())
    seed_ids = {r["id"] for r in seeds}
    sources = [r for path in ledgers for r in json.loads(path.read_text())]
    eligible, direct, reasons, excluded = pool(attacks, seed_ids, sources)
    # Fail rather than silently put an unknown technique in the wrong stratum.
    for r in eligible:
        if r["technique"] not in TECHNIQUES:
            raise ValueError(f"Unmapped technique: {r['technique']}")
    salt = salt or secrets.token_hex(32)
    chosen = select(eligible, size, salt)
    def counts(rows, key):
        return dict(sorted(Counter(key(r) for r in rows).items()))
    manifest = {
        "schema": 2,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "reserved_ids_only_custodian_attestation_and_system_freeze_pending",
        "criterion": "No run or substantive/unresolved source names the attack, its seed, or a sibling attack. Dataset copies and selection/config data alone are not exposure.",
        "sampling": "Balance available categories, then evasion strata within category; salted SHA256 tie-break; one attack per seed.",
        "salt": salt,
        "requested_pairs": size,
        "reserved_pairs": len(chosen),
        "direct_criterion_attacks": len(direct),
        "direct_criterion_seed_groups": len({r['seed_id'] for r in direct}),
        "eligible_attacks": len(eligible),
        "eligible_seed_groups": len({r['seed_id'] for r in eligible}),
        "sibling_exclusions": sorted(r['id'] for r in direct if r not in eligible),
        "eligible_by_category": counts(eligible, lambda r: r['risk_category']),
        "eligible_by_evasion": counts(eligible, lambda r: TECHNIQUES[r['technique']]),
        "selected_by_category": counts(chosen, lambda r: r['risk_category']),
        "selected_by_evasion": counts(chosen, lambda r: TECHNIQUES[r['technique']]),
        "missing_categories": sorted({r['risk_category'] for r in attacks} - {r['risk_category'] for r in eligible}),
        "exposure_unique_ids_by_reason_overlapping": {k: len(v) for k,v in sorted(reasons.items())},
        "excluded_unique_ids": len(excluded),
        "source_ledgers": {str(p.resolve()): digest(p.read_bytes()) for p in ledgers},
        "dataset_sha256": {name: digest((dataset/name).read_bytes()) for name in ('injected.json','seeds.json')},
        "sampler_sha256": digest(Path(__file__).read_bytes()),
        "limits": [
            "Eligibility is based on retained local records, not absence from disk.",
            "No case prompt, setup, solution or judge outcome was displayed by this sampler.",
            "Custodian must attest no undocumented content exposure before launch.",
            "Do not inspect reserved contents or use them for policy/baseline tuning.",
            "These five supported categories do not represent all A3S categories.",
            "Previously evaluated or subsequently exposed cases remain development cases.",
        ],
        "cases": [{"id":r['id'], "seed_id":r['seed_id']} for r in chosen],
    }
    output.mkdir(parents=True)
    data = (json.dumps(manifest, indent=2) + '\n').encode()
    (output/'manifest.json').write_bytes(data)
    (output/'manifest.sha256').write_text(digest(data)+'  manifest.json\n')
    # Evidence ledger stores IDs/paths/categories only, never prompt text.
    (output/'exposure-ledger.json').write_text(json.dumps([
        {**r, "reason": exposure_kind(r['path'])} for r in sources
    ], indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ('status','reserved_pairs','direct_criterion_attacks','eligible_attacks','eligible_seed_groups','selected_by_category','selected_by_evasion','missing_categories')}))
    return manifest


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dataset', type=Path, required=True)
    p.add_argument('--ledger', type=Path, action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--size', type=int, default=100)
    a = p.parse_args()
    reserve(a.dataset,a.ledger,a.output,a.size)
