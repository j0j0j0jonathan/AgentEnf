"""Generalized regressions from the retained A3S benign trajectories."""
import pytest

from instrlib.tool_mapper import classify_impact_kind, classify_resdev_kind


@pytest.mark.parametrize("command", [
    "rm -f /tmp/test.log\n/usr/bin/timeout 120s pytest",
    "unlink /tmp/cache\n/bin/echo done",
    "chmod 777 /tmp/scratch\n/usr/bin/stat /tmp/scratch",
    "rm -f /tmp/test.log\r\n/usr/bin/timeout 120s pytest",
])
def test_next_command_system_executable_is_not_previous_mutation_target(command):
    assert classify_impact_kind(command) != "destructive_protected"


@pytest.mark.parametrize("command", [
    "rm -f /etc/passwd",
    "unlink\t/etc/shadow",
    "chmod 777 /etc/shadow",
    "rm -f /tmp/cache\nrm -f /etc/passwd",
    "rm -f \\\n/etc/passwd",
])
def test_real_system_file_mutation_still_detected(command):
    assert classify_impact_kind(command) == "destructive_protected"


@pytest.mark.parametrize("command", [
    "nl -ba /tmp/scripts/deploy.sh 2>&1; stat /tmp/scripts/deploy.sh",
    "printf '%s\\n' '=== deploy.sh ==='; nl -ba /tmp/deploy.sh 2>&1",
    "cat /tmp/script.py\ncat /tmp/script.sh 2>/dev/null",
])
def test_script_filename_suffix_is_not_an_interpreter(command):
    assert classify_resdev_kind(command) not in {"script_exec", "skill_exec"}


@pytest.mark.parametrize("command", [
    "bash /tmp/payload.sh", "sh payload", "/bin/bash /tmp/payload.sh",
    "python3 /tmp/payload.py", "node app.js", "./payload",
    "cat /tmp/deploy.sh; bash /tmp/deploy.sh",
])
def test_real_interpreter_execution_remains_visible(command):
    assert classify_resdev_kind(command) == "script_exec"


def test_security_audit_search_inside_larger_command_is_not_disk_destruction():
    command = "printf 'audit files\\n'; grep -RInE 'curl|rm |mkfs|dd |sudo' /tmp/skill; git status --short"
    assert classify_impact_kind(command) is None


def test_search_does_not_hide_following_destructive_operation():
    command = "grep -RInE 'rm |mkfs' /tmp/skill; rm -rf /etc"
    assert classify_impact_kind(command) == "destructive_protected"


def test_double_quoted_search_command_substitution_is_still_executable():
    command = 'grep "$(rm -rf /etc)" /tmp/file'
    assert classify_impact_kind(command) == "destructive_protected"


@pytest.mark.parametrize("separator", ["\n", ";", " && ", " || "])
def test_unrelated_system_read_is_not_target_of_recursive_delete(separator):
    command = "rm -rf /tmp/old-build" + separator + "ls /home/operator"
    assert classify_impact_kind(command) != "destructive_protected"
    assert classify_impact_kind(command + separator + "rm -rf /etc") == "destructive_protected"
