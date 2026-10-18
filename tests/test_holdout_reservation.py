import json
import pytest
from experiments.paper.reserve_holdout import exposure_kind, pool, reserve, select


def row(i, seed, category="A", technique="Direct request"):
    return dict(
        id=i,
        seed_id=seed,
        risk_category=category,
        technique=technique,
        turns=["DO NOT COPY THIS PROMPT"],
    )


def test_exposure_distinguishes_possession_and_use():
    assert exposure_kind("/data/dataset_a3s.jsonl") == "dataset_copy"
    assert exposure_kind("/selection/manifest.json") == "selection_or_config"
    assert exposure_kind("/selection/review.md") == "substantive_or_unresolved"
    assert exposure_kind("/config/regression.py") == "substantive_or_unresolved"
    assert exposure_kind("/tests/config/fixture.yaml") == "substantive_or_unresolved"
    assert exposure_kind("/live/unit-seed-0001/config.yaml") == "run_evidence"
    assert exposure_kind("/unknown/record.txt") == "substantive_or_unresolved"


def test_exposed_sibling_excludes_whole_seed_family():
    rows = [
        row("unit-attack-0001", "unit-seed-0001"),
        row("unit-attack-0002", "unit-seed-0001"),
        row("unit-attack-0003", "unit-seed-0002"),
        row("unit-attack-0004", "unit-seed-0003"),
    ]
    evidence = [
        {"path": "/live/rollout.json", "ids": ["unit-attack-0001"]},
        {"path": "/notes.md", "ids": ["unit-seed-0003"]},
        {"path": "/selection/all.json", "ids": ["unit-attack-0003", "unit-seed-0002"]},
    ]
    eligible, direct, _, _ = pool(
        rows, {"unit-seed-0001", "unit-seed-0002", "unit-seed-0003"}, evidence
    )
    assert [r["id"] for r in direct] == ["unit-attack-0002", "unit-attack-0003"]
    assert [r["id"] for r in eligible] == ["unit-attack-0003"]


def test_deterministic_stratification_and_no_duplicate_seeds():
    rows = [
        row(
            f"unit-attack-{i:04}",
            f"unit-seed-{i // 2:04}",
            "A" if i < 10 else "B",
            "Direct request" if i % 2 else "Staged multi-step",
        )
        for i in range(20)
    ]
    result = select(rows, 8, "fixed")
    assert result == select(list(reversed(rows)), 8, "fixed")
    assert len({r["seed_id"] for r in result}) == 8
    assert sum(r["risk_category"] == "A" for r in result) == 4
    with pytest.raises(ValueError):
        select(rows, 11, "fixed")


def test_reservation_never_copies_prompts_and_cannot_be_overwritten(tmp_path):
    dataset = tmp_path / "data"
    dataset.mkdir()
    (dataset / "injected.json").write_text(json.dumps([row("unit-attack-0001", "unit-seed-0001")]))
    (dataset / "seeds.json").write_text(
        json.dumps([{"id": "unit-seed-0001", "turns": ["PRIVATE"]}])
    )
    ledger = tmp_path / "sources.json"
    ledger.write_text("[]")
    output = tmp_path / "reserved"
    reserve(dataset, [ledger], output, 1, "fixed")
    assert set(p.name for p in output.iterdir()) == {
        "manifest.json",
        "manifest.sha256",
        "exposure-ledger.json",
    }
    text = "".join(p.read_text() for p in output.iterdir())
    assert "DO NOT COPY" not in text and "PRIVATE" not in text
    with pytest.raises(FileExistsError):
        reserve(dataset, [ledger], output, 1, "fixed")
