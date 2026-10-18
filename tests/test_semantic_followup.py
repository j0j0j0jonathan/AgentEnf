import json

from experiments.paper import semantic_followup as f
from experiments.paper import calibrate_semantics as c


def test_context_contrasts_are_prelabelled_separate_inputs():
    cases = f.reply_cases()
    assert len(cases) == 18 and len({c["id"] for c in cases}) == 18
    labels = {row["id"].split(":")[1]: row["expected"] for row in cases}
    for name in ("old-user-command", "old-document-command", "old-assistant-command", "cosmetic-format"):
        assert labels[name] == 0
    for name in ("new-command", "changed-target", "changed-flags", "assembled-command", "assembled-dataflow",
                 "claimed-old-command", "endorsement-after-disclaimer", "server-history-unavailable", "omitted-command"):
        assert labels[name] == 1
    for row in cases:
        data = json.loads(row["input"])
        assert data["schema"] == "reply-evidence-v1"
        assert "expected" not in data and "label_basis" not in data


def test_preparation_preserves_old_results_and_freezes_three_arms(tmp_path):
    previous = tmp_path / "previous"
    previous.mkdir()
    cases = [{"id": str(i), "target": "content_disclosure" if i < 6 else "authored_capability",
              "input": "fixture " + str(i), "expected": "benign"} for i in range(14)]
    (previous / "cases.json").write_text(json.dumps({"cases": cases}))
    (previous / "manifest.json").write_text(json.dumps({"cases_sha256": f.sha(previous / "cases.json")}))
    (previous / "results.jsonl").write_text("preserved recorded results\n")
    before = f.sha(previous / "results.jsonl")
    dest = f.prepare(previous, tmp_path / "followup")
    manifest = json.loads((dest / "manifest.json").read_text())
    assert manifest["planned_calls"] == 44
    assert list(manifest["arms"]) == ["current-controls", "candidate", "contextual-reply"]
    assert manifest["previous_results_sha256"] == before == f.sha(previous / "results.jsonl")
    assert c.check(dest / "current-controls")["planned"] == 6
    assert c.check(dest / "candidate")["planned"] == 20
    assert c.check(dest / "contextual-reply")["planned"] == 18
    assert json.loads((dest / "candidate/cases.json").read_text())["cases"][:14] == cases
