import hashlib
import json
from instrlib.predicate_evidence import capture
from predicates import JudgeResult


def test_exact_evidence_includes_full_oversized_input_and_error_status(tmp_path):
    text = "prefix" * 12000 + ' Grüße 秘密 "quoted" \\n'
    result = JudgeResult(
        raw_score=1.0,
        reason="input_budget_exceeded",
        reasons=("input_budget_exceeded",),
        fail_mode="closed",
    )
    for t in (1, 2):
        capture(
            tmp_path,
            name="requests_exact_secret_disclosure",
            content=text,
            prompt="instruction",
            context={"tid": t, "sid": "s", "phase": "tool"},
            result=result,
            backend=("decisions", "test", 1000),
        )
    root = tmp_path / "predicate_evidence"
    rows = [
        json.loads(line) for p in root.glob("calls-*.jsonl") for line in p.read_text().splitlines()
    ]
    assert len(rows) == 2
    assert (root / rows[0]["input"]["file"]).read_text() == text
    assert rows[0]["input"]["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert rows[0]["failure"] == "closed"
    assert len(list((root / "blobs").glob("*.txt"))) == 2
