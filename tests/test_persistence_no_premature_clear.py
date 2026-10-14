"""Regression cases for proposal clearing and full executable identity."""

import json
import os
from pathlib import Path
import pytest
import yaml
from instrlib import Event, Enforcer
from instrlib.persistence_paths import command_targets, persistence_path_events
from instrlib.tool_mapper import map_tool_call

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "command,path",
    [
        ('/usr/bin/python3 "/app/my job.py"', "/app/my job.py"),
        ("/usr/bin/python3 /app/é.py", "/app/é.py"),
        ("/usr/bin/python3.11 /app/job.py", "/app/job.py"),
        ("/usr/local/bin/php /app/x.php", "/app/x.php"),
        ("/usr/bin/nice -n 5 /app/job.sh", "/app/job.sh"),
        ("/usr/bin/flock -n /tmp/lock /app/job.sh", "/app/job.sh"),
    ],
)
def test_full_executable_paths(command, path):
    targets, unknown = command_targets(command)
    assert targets == {path}
    assert not unknown


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/cat /app/job.sh",
        "/usr/bin/echo hello >/app/job.sh",
        "/usr/bin/custom-launcher /app/job.sh",
    ],
)
def test_argument_or_redirect_never_becomes_execution_target(command):
    targets, unknown = command_targets(command)
    assert "/app/job.sh" not in targets
    if ">" not in command:
        assert unknown


def test_native_removal_uses_real_mapper_and_job_identity():
    for job in ["job-1", "job-2"]:
        args = {"action": "remove", "jobId": job, "command": "/app/job.sh"}
        mapped = map_tool_call(1, "c", "cron", args)
        canonical = next(e.args[2] for e in mapped if e.name == "ToolCall")
        events = persistence_path_events(
            1, "c", canonical, args, "runtime-A", mapped, raw_tool_name="cron"
        )
        assert (
            Event(
                "Classify",
                1,
                "c",
                "schedule_removal_proposed_id",
                json.dumps(["runtime-A", job], separators=(",", ":")),
            )
            in events
        )
        assert not any(
            e.args[2] in {"schedule_removed_target_v2", "rewrite_or_delete_target_v2"}
            for e in events
        )


@pytest.mark.parametrize(
    "outcome", ["not_executed", "failed", "unknown", "runtime_reported_complete"]
)
def test_cleanup_claim_cannot_clear_without_verified_lifecycle(tmp_path, outcome):
    binary = Path(os.environ.get("ENFGUARD_BIN", ""))
    if not binary.is_file():
        pytest.skip("requires real monitor")
    pack = yaml.safe_load((ROOT / "examples/presets/release-candidate.yaml").read_text())
    formula = tmp_path / "p.mfotl"
    formula.write_text(next(p["mfotl"] for p in pack["policies"] if p["id"] == "persistence_v1"))
    enf = Enforcer(str(binary), str(ROOT / "enfguard.sig"), str(formula))
    enf.start()
    target = '["A","/app/job.sh"]'

    def batch(t, dim):
        return [
            Event("PolicyActive", t, "persistence_v1"),
            Event("ToolPlanned", t, str(t), "file_write", "{}"),
            Event("Classify", t, str(t), dim, target),
        ]

    try:
        enf.query(batch(1, "dangerous_write_target_v2"), 1)
        # Even legacy clear facts must no longer weaken the candidate rule.
        enf.query(
            batch(2, "rewrite_or_delete_target_v2")
            + [Event("Classify", 2, "2", "execution_outcome", outcome)],
            2,
        )
        result = enf.query(batch(3, "schedule_target_v2"), 3)
    finally:
        enf.stop()
    assert any(
        e["name"] == "Block" and "dangerous_script_then_schedule" in str(e)
        for e in result.get("cause", [])
    )


def test_path_traversal_does_not_invent_symlink_resolution():
    targets, unknown = command_targets("/bin/bash /app/link/../job.sh")
    assert not targets and unknown


@pytest.mark.parametrize('command,should_block', [
    ('/usr/bin/python3 "/app/my job.py"', True),
    ('/usr/bin/cat "/app/my job.py"', False),
    ('/usr/bin/echo hello >"/app/my job.py"', False),
])
def test_monitor_distinguishes_execution_from_data_argument(tmp_path, command, should_block):
    binary = Path(os.environ.get('ENFGUARD_BIN', ''))
    if not binary.is_file():
        pytest.skip('requires real monitor')
    pack = yaml.safe_load((ROOT / 'examples/presets/release-candidate.yaml').read_text())
    formula = tmp_path / 'p.mfotl'
    formula.write_text(next(p['mfotl'] for p in pack['policies'] if p['id'] == 'persistence_v1'))
    enforcer = Enforcer(str(binary), str(ROOT / 'enfguard.sig'), str(formula))
    enforcer.start()
    target = '["A","/app/my job.py"]'
    args = {'action': 'add', 'command': command}
    mapped = map_tool_call(2, 'c2', 'cron', args)
    call = next(e for e in mapped if e.name == 'ToolCall')
    try:
        enforcer.query([Event('Classify', 1, 'c1', 'dangerous_write_target_v2', target)], 1)
        result = enforcer.query([
            Event('PolicyActive', 2, 'persistence_v1'), Event('ToolPlanned', *call.args),
            *mapped, *persistence_path_events(2, 'c2', call.args[2], args, 'A', mapped, raw_tool_name='cron'),
        ], 2)
    finally:
        enforcer.stop()
    blocks = [e for e in result.get('cause', []) if e['name'] == 'Block' and 'dangerous_script_then_schedule' in str(e)]
    assert bool(blocks) == should_block
