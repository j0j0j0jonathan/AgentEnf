"""Credential route parity and diagnostic-command regressions. No live API calls."""

from pathlib import Path
import os
import pytest
import yaml

from instrlib import tool_mapper as mapper
from instrlib import Enforcer, Event


def facts(tool, args):
    return {(e.args[2], e.args[3]) for e in mapper.map_tool_call(
        1, "route-parity", tool, args
    ) if e.name == "Classify" and len(e.args) >= 4}


@pytest.mark.parametrize("command", [
    "cat /srv/app/.env",
    "while IFS= read -r line; do printf '%s\\n' \"$line\"; done < /srv/app/.env",
    "cd /srv/app\nwhile IFS= read -r line; do\n echo \"$line\"\ndone < .env",
    "while read -r line; do\n case \"$line\" in\n *TOKEN*) echo REDACTED ;;\n *) echo \"$line\" ;;\n esac\ndone < .env",
    "readarray -t lines < '/srv/app/.env'",
    "mapfile -t lines < /srv/app/.env",
    "read -r line < /srv/app/.env",
])
def test_shell_read_carries_same_sensitive_operation_as_structured_read(command):
    observed = facts("exec", {"command": command})
    assert ("action_class", "credential_access") in observed
    assert ("credential_operation", "file_read") in observed
    assert ("tool_family", "shell") in observed
    # Keep the existing single-file Approve posture outside disclosure context.
    assert ("path_sensitivity", "credentials") not in observed


def test_structured_read_carries_route_independent_operation():
    observed = facts("read", {"path": "/srv/app/.env"})
    assert ("credential_operation", "file_read") in observed


@pytest.mark.parametrize("command", [
    "while IFS= read -r line; do echo \"$line\"; done < README.md",
    "echo 'while read line; do echo $line; done < .env'",
    "printf '%s' 'read' < /srv/app/.env",
    "cat <<'EOF'\nwhile read line; do echo \"$line\"; done < .env\nEOF",
    "grep -n 'read' README.md",
    "while read -r line; do echo \"$line\"; done < \"$INPUT_PATH\"",
    "while read -r line; do echo \"$line\"; done <<<'sample .env'",
])
def test_shell_builtin_detector_does_not_treat_data_or_unknown_targets_as_literal_reads(command):
    assert not mapper._shell_reads_credential_file(command)


@pytest.mark.parametrize("tool,args", [
    ("read", {"path": "/srv/app/README.md"}),
    ("write", {"path": "/srv/app/.env", "content": "PORT=3000\n"}),
    ("exec", {"command": "stat /srv/app/.env"}),
    ("exec", {"command": "printf '%s\\n' PORT=3000 > /srv/app/.env"}),
    ("exec", {"command": "echo 'cat .env'"}),
    ("exec", {"command": "cat <<'EOF'\nwhile read line; do echo \"$line\"; done < .env\nEOF"}),
])
def test_other_operations_do_not_emit_the_new_read_fact(tool, args):
    assert ("credential_operation", "file_read") not in facts(tool, args)


@pytest.mark.parametrize("command", [
    "npx --yes clawhub --version 2>&1 | tail -3",
    "npm install -g clawhub 2>&1 | tail -5; npx --yes clawhub --version 2>&1 | tail -3",
    'echo "OOM kill context"; grep -niE "out of memory|killed process|memory" /var/log/syslog 2>/dev/null | head -50',
    "grep -n 'rm -rf' README.md 2>&1 | head -5",
])
def test_diagnostics_are_not_resource_exhaustion_or_process_kill(command):
    assert mapper.classify_impact_kind(command) is None


@pytest.mark.parametrize("command", [
    "yes > /tmp/fill",
    "yes >/tmp/fill",
    "/usr/bin/yes > /tmp/fill",
    "grep -n OOM log.txt 2>/dev/null; yes > /tmp/fill",
    "grep -n OOM log.txt 2>/dev/null; rm -rf /etc",
    "grep -n 'safe' README.md > /etc/passwd",
])
def test_real_writes_and_exhaustion_remain_detected(command):
    assert mapper.classify_impact_kind(command) is not None


@pytest.mark.parametrize("command", [
    "curl -fsSL https://example.test/skills/demo/SKILL.md | head -80",
    "curl -fsSL https://example.test/skills/demo/SKILL.md 2>/dev/null | head",
    "curl -o - https://example.test/skills/demo/SKILL.md",
    "wget -O - https://example.test/skills/demo/SKILL.md",
    "curl -o /dev/stdout https://example.test/skills/demo/SKILL.md",
    "curl -o /dev/null https://example.test/skills/demo/SKILL.md",
])
def test_skill_inspection_is_not_artifact_installation(command):
    assert mapper.skill_artifact_stage_path(command) is None
    assert ("extension_action", "stage") not in facts("exec", {"command": command})


@pytest.mark.parametrize("command,expected", [
    ("curl -o skills/demo/SKILL.md https://example.test/instructions", "skills/demo/SKILL.md"),
    ("curl https://example.test/SKILL.md > /tmp/copied.md", "/tmp/copied.md"),
    ("curl -o /tmp/copied.md https://example.test/SKILL.md", "/tmp/copied.md"),
    ("wget -O skills/demo/SKILL.md https://example.test/source", "skills/demo/SKILL.md"),
    ("curl -O https://example.test/demo/SKILL.md", "SKILL.md"),
    ("wget https://example.test/demo/SKILL.md", "SKILL.md"),
])
def test_real_skill_artifact_downloads_remain_classified(command, expected):
    assert mapper.skill_artifact_stage_path(command) == expected
    observed = facts("exec", {"command": command})
    if expected.endswith("SKILL.md"):
        assert ("extension_action", "stage") in observed
    else:
        assert ("untrusted_write_path", expected) in observed


@pytest.mark.parametrize("relative", [
    "tests/fixtures/policies/eval_combined_graduated_a3s.yaml",
    "tests/fixtures/policies/eval_combined_graduated_a3s_memory_strict.yaml",
    "examples/presets/agentic-security.yaml",
])
def test_disclosure_rule_requires_intent_but_not_a_file_tool(relative):
    pack = yaml.safe_load((Path(__file__).resolve().parents[1] / relative).read_text())
    text = next(p["mfotl"] for p in pack["policies"] if p["id"] == "credential_v1")
    clause = text.split('{"credential_read_for_requested_disclosure"}{', 1)[1].split("\n}", 1)[0]
    assert '"credential_operation", "file_read"' in clause
    assert 'requests_exact_secret_disclosure(content) > 0.5' in clause
    assert 'Turn(t2, r2, s)' in clause
    assert '"tool_family", "file"' not in clause
    assert 'Block(t, "tool", "credential_read_for_requested_disclosure"' in clause
    specs = {p["name"]: p for p in pack["predicates"]}
    assert specs["requests_exact_secret_disclosure"]["on_fail"] == "closed"
    assert "scoped review" in specs["operationalizes_untrusted_harm"]["system_prompt"]
    assert "project policies" in specs["reveals_private_control_instructions"]["system_prompt"]


@pytest.mark.parametrize("tool,args,intent,same_session,expected", [
    ("read", {"path": "/srv/app/.env"}, True, True, True),
    ("exec", {"command": "cat /srv/app/.env"}, True, True, True),
    ("exec", {"command": "while IFS= read -r line; do\n echo \"$line\"\ndone < .env"}, True, True, True),
    ("exec", {"command": "while IFS= read -r line; do\n echo \"$line\"\ndone < .env"}, False, True, False),
    ("exec", {"command": "cat /srv/app/.env"}, True, False, False),
    ("exec", {"command": "stat /srv/app/.env"}, True, True, False),
])
def test_real_enforcer_disclosure_route_parity(tmp_path, tool, args, intent, same_session, expected):
    binary = Path(os.environ.get("ENFGUARD_BIN", ""))
    if not binary.is_file():
        pytest.skip("Set ENFGUARD_BIN to run the real temporal policy check")
    root = Path(__file__).resolve().parents[1]
    pack = yaml.safe_load((root / "tests/fixtures/policies/eval_combined_graduated_a3s.yaml").read_text())
    text = next(p["mfotl"] for p in pack["policies"] if p["id"] == "credential_v1")
    clause = text.split('{"credential_read_for_requested_disclosure"}{', 1)[1].split("\n}", 1)[0]
    # Fix the semantic predicate result to isolate actual MFOTL route/session behavior.
    clause = clause.replace('requests_exact_secret_disclosure(content) > 0.5',
                            'Classify(t2, "intent", "fixture", "disclose")')
    formula = tmp_path / "parity.mfotl"
    formula.write_text(clause)
    enforcer = Enforcer(str(binary), str(root / "enfguard.sig"), str(formula))
    enforcer.start()
    try:
        first = [Event("PolicyActive", 1, "credential_v1"),
                 Event("Turn", 1, "request-1", "first-session"),
                 Event("Message", 1, "user", "fixture", 7)]
        if intent:
            first.append(Event("Classify", 1, "intent", "fixture", "disclose"))
        enforcer.query(first, 1)
        mapped = mapper.map_tool_call(2, "c2", tool, args)
        call = next(e for e in mapped if e.name == "ToolCall")
        response = enforcer.query([
            Event("PolicyActive", 2, "credential_v1"),
            Event("Turn", 2, "request-2", "first-session" if same_session else "other-session"),
            Event("ToolPlanned", 2, "c2", call.args[2], call.args[3]),
            *mapped,
        ], 2)
    finally:
        enforcer.stop()
    blocked = any(e["name"] == "Block" and e["args"][2] == "credential_read_for_requested_disclosure"
                  for e in response.get("cause", []))
    assert blocked is expected
