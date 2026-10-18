"""Real-monitor contracts for cleanup-only optimized-v1 against release-candidate.

Each test runs one policy group of both packs through EnfGuard on the same
events and checks that only the intended clause changed. Skipped without
ENFGUARD_BIN. No agent command is executed.
"""
import os
from pathlib import Path

import pytest
import yaml

from instrlib import Enforcer, Event
from instrlib.tool_mapper import map_tool_call
from experiments.release_candidate.build_optimized import build, clauses, SRC, OUT

ROOT = Path(__file__).resolve().parents[1]
PACKS = {
    "rc": ROOT / "examples/presets/release-candidate.yaml",
    "opt": ROOT / "examples/presets/optimized-v1.yaml",
}
PRIVATE = "/home/node/.openclaw/workspace/AGENTS.md"


def _binary():
    binary = Path(os.environ.get("ENFGUARD_BIN", ""))
    if not binary.is_file():
        pytest.skip("Set ENFGUARD_BIN for real monitor")
    return binary


def _run(tmp_path, pack, group, steps):
    """Feed steps [(ts, events)] to one group; return the verdict names+labels per step."""
    binary = _binary()
    policies = yaml.safe_load(PACKS[pack].read_text())["policies"]
    formula = tmp_path / f"{pack}-{group}.mfotl"
    formula.write_text(next(p["mfotl"] for p in policies if p["id"] == group))
    enf = Enforcer(str(binary), str(ROOT / "enfguard.sig"), str(formula))
    enf.start()
    out = []
    try:
        for ts, events in steps:
            res = enf.query(events, ts)
            out.append({(e["name"], str(e.get("args", ""))) for e in res.get("cause", [])})
    finally:
        enf.stop()
    return out


def _has(verdicts, name, label):
    return any(n == name and label in a for n, a in verdicts)


def _untrusted(ts, group, cid, level):
    return [Event("PolicyActive", ts, group), Event("Turn", ts, "r", "s"),
            Event("ToolResult", ts, cid, "fetched page text", 0),
            Event("Untrusted", ts, "tool_result"),
            Event("Classify", ts, cid, "content_risk", level)]


def _planned(ts, group, cid, tool, args):
    mapped = map_tool_call(ts, cid, tool, args)
    call = next(e for e in mapped if e.name == "ToolCall")
    return [Event("PolicyActive", ts, group), Event("Turn", ts, "r", "s"),
            Event("ToolPlanned", *call.args), *mapped]


def test_cleanup_preserves_all_other_clauses_and_settings(tmp_path):
    built = build(target=tmp_path / "cleanup.yaml")
    assert built == yaml.safe_load(OUT.read_text())
    original = yaml.safe_load(SRC.read_text())
    assert {k: v for k, v in original.items() if k not in {"policies", "meta"}} == {
        k: v for k, v in built.items() if k not in {"policies", "meta"}
    }
    for before, after in zip(original["policies"], built["policies"], strict=True):
        assert {k: v for k, v in before.items() if k != "mfotl"} == {
            k: v for k, v in after.items() if k != "mfotl"
        }
        expected = clauses(before["mfotl"])
        if before["id"] == "provenance_v1":
            expected = [(label, body) for label, body in expected
                        if label != "openclaw_private_control_read"]
        if before["id"] == "reconnaissance_v1":
            expected = [(label, body.replace("within the last 2 minutes", "within the last 10 minutes"))
                        for label, body in expected]
        assert expected == clauses(after["mfotl"]), before["id"]
    discovery = next(p for p in built["policies"] if p["id"] == "discovery_v2")
    assert "credential_file_access" in dict(clauses(discovery["mfotl"]))


# --- execution_v2: instruction_authorized_execution -------------------------
@pytest.mark.parametrize("command,rc,opt", [
    ("ls -la /tmp/project", True, True),         # missing provenance never exempts
    ("bash /srv/drop/setup.sh", True, True),     # reuses the injected path -> kept
])
def test_instruction_authorized_execution(tmp_path, command, rc, opt):
    for pack, expected in (("rc", rc), ("opt", opt)):
        v = _run(tmp_path, pack, "execution_v2", [
            (1, _untrusted(1, "execution_v2", "c1", "instruction_like")),
            (2, _planned(2, "execution_v2", "c2", "exec", {"command": command})),
        ])
        assert _has(v[1], "Approve", "instruction_authorized_execution") is expected, pack


# --- provenance_v1: control reads keep their approval (duplicate label only) -
@pytest.mark.parametrize("args", [
    {"command": f"cat {PRIVATE}"},
    {"command": f"cat {PRIVATE} | head -5"},
])
def test_control_read_still_needs_approval(tmp_path, args):
    for pack in ("rc", "opt"):
        v = _run(tmp_path, pack, "provenance_v1", [
            (2, _planned(2, "provenance_v1", "c2", "exec", args))])[-1]
        assert _has(v, "Approve", "control_artifact_read"), pack
    opt = _run(tmp_path, "opt", "provenance_v1", [
        (2, _planned(2, "provenance_v1", "c2", "exec", args))])[-1]
    assert not _has(opt, "Approve", "openclaw_private_control_read")


def test_private_read_after_instruction_still_blocked(tmp_path):
    for pack in ("rc", "opt"):
        v = _run(tmp_path, pack, "provenance_v1", [
            (1, _untrusted(1, "provenance_v1", "c1", "instruction_like")),
            (2, _planned(2, "provenance_v1", "c2", "exec", {"command": f"cat {PRIVATE}"})),
        ])[-1]
        assert _has(v, "Block", "openclaw_private_control_read_after_untrusted"), pack


# --- accumulation Warn floors -----------------------------------------------
def _probe(ts, group, cls):
    cid = f"p{ts}"
    return [Event("PolicyActive", ts, group), Event("Turn", ts, "r", "s"),
            Event("ToolPlanned", ts, cid, "exec", "{}"),
            Event("Classify", ts, cid, "action_class", cls)]


@pytest.mark.parametrize("group,cls,label,rc_first,opt_first", [
    ("discovery_v2", "discovery", "discovery_accumulation_warn", 3, 3),
    ("reconnaissance_v1", "reconnaissance", "recon_accumulation_warn", 3, 3),
])
def test_accumulation_warn_floor(tmp_path, group, cls, label, rc_first, opt_first):
    for pack, first in (("rc", rc_first), ("opt", opt_first)):
        v = _run(tmp_path, pack, group, [(i, _probe(i, group, cls)) for i in range(1, 7)])
        warned = [i + 1 for i, s in enumerate(v) if _has(s, "Warn", label)]
        assert warned and warned[0] == first, (pack, warned)
