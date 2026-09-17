"""Tool-name aliases and conservative inference from structured arguments.

This module determines the mechanism to inspect, not whether it is permitted.
"""

from typing import Any, Dict, Optional

_FILE_EDITOR_NAMES = {"str_replace_based_editor", "text_editor", "str_replace_editor"}

_BASH_NAMES = {
    "bash",
    "shell",
    "terminal",
    "exec",
    "exec_shell",
    "run_command",
    "execute",
    "execute_shell",
    "run",
}

_FILEREAD_NAMES = {"read_file", "read", "view", "cat", "get_file", "open_file", "file_read"}

_FILEWRITE_NAMES = {
    "write_file",
    "write",
    "append",
    "create_file",
    "save_file",
    "put_file",
    "file_write",
    "edit_file",
    "code_edit",
    "insert",
    "undo_edit",
    "edit",
}

_FILEDEL_NAMES = {"delete_file", "remove_file", "unlink", "rm", "file_delete"}

_NETWORK_NAMES = {
    "web_fetch",
    "fetch",
    "http_request",
    "http_get",
    "http_post",
    "browser",
    "navigate",
    "curl",
    "wget",
    "download",
    "web_search",
    "search",
    "browse_web",
}

_CODE_NAMES = {
    "python",
    "code_execution",
    "code_exec",
    "exec_python",
    "run_python",
    "repl",
    "jupyter",
    "execute_code",
}

_COMPUTER_NAMES = {"computer", "computer_use", "gui", "desktop"}

_MEMORY_NAMES = {"memory_search", "memory_get", "search_memory", "get_memory"}

_DEVICE_NAMES = {"nodes", "node", "devices", "device", "device_pairing"}

_CONTROL_PLANE_NAMES = {"gateway", "control_plane", "agent_gateway"}

_PROCESS_NAMES = {"process", "process_control", "session", "session_status"}

_EXTENSION_NAMES = {
    "debug-pro",
    "test-runner",
    "code-review",
    "analyze_pr",
    "pr-reviewer",
    "document-pro",
    "summarize-pro",
    "log-analyzer",
    "data-analysis",
    "data_analysis_skill",
    "multi_tool_analysis",
    "duckdb_query",
    "duckdb_cli_exec",
    "duckdb-cli-ai-skills",
    "file-manager",
    "file-manager.organize",
    "file-organizer-skill",
    "filesystem",
    "filesystem.list_dir",
    "file_inspector",
    "workspace_inspect",
    "workspace_inspector",
    "system-info",
    "system-resource-monitor",
    "system_resource_monitor.get_health_report",
    "organize",
    "skill_guidance",
    "skill_advice",
}

_SEARCH_NAMES = {
    "glob",
    "grep",
    "ripgrep",
    "rg",
    "fd",
    "find_files",
    "search_files",
    "file_search",
    "grep_search",
    "glob_search",
    "list",
    "list_dir",
    "list_files",
    "list_dir_recursive",
}


def _infer_tool_category_from_payload(tool_input: Dict[str, Any]) -> Optional[str]:
    """Infer a known tool family from common structured argument shapes.

    This is the deterministic fallback for novel tool names in Tier B: if a
    backend calls a tool `foo_runner` but passes `{command: ...}`, treat it as a
    shell tool; if it passes `{url: ...}`, treat it as network; and so on. The
    inference is intentionally conservative and only uses high-signal fields.
    """
    if not isinstance(tool_input, dict):
        return None
    keys = {str(k).lower() for k in tool_input.keys()}
    if keys & {"command", "cmd", "shell_command"}:
        return "bash"
    if keys & {"url", "uri", "endpoint"}:
        return "network"
    if keys & {"code", "source", "script"}:
        return "code"
    if keys & {"pattern", "glob", "regex"}:
        return "search"
    if keys & {"path", "file_path", "filename", "file", "filepath"}:
        if keys & {
            "content",
            "text",
            "file_text",
            "new_str",
            "new_string",
            "newText",
            "new_text",
            "data",
            "body",
        }:
            return "file_write"
        return "file_read"
    return None


def _categorize_tool(tool_name: str) -> Optional[str]:
    """
    Return canonical category for a tool_name, or None if unrecognized.

    Priority matters: check specific names before substring patterns to avoid
    misclassifying str_replace_based_editor as "file_write" due to "replace".
    """
    name = tool_name.lower().strip()

    # Exact-name checks first (highest priority)
    if name in _FILE_EDITOR_NAMES:
        return "file_editor"  # subcommand-dispatched, handled separately
    if name in _COMPUTER_NAMES:
        return "computer"
    if name in _MEMORY_NAMES:
        return "memory"
    if name in _DEVICE_NAMES:
        return "device"
    if name in _CONTROL_PLANE_NAMES:
        return "control_plane"
    if name in _PROCESS_NAMES:
        return "process"
    if name in _BASH_NAMES:
        return "bash"
    if name in _FILEDEL_NAMES:
        return "file_delete"
    if name in _FILEREAD_NAMES:
        return "file_read"
    if name in _FILEWRITE_NAMES:
        return "file_write"
    if name in _SEARCH_NAMES:
        return "search"
    if name in _NETWORK_NAMES:
        return "network"
    if name in _CODE_NAMES:
        return "code"
    if name in _EXTENSION_NAMES:
        return "extension"

    # Substring fallback, order matters
    if "skill" in name and not any(
        n in name for n in ("install", "add", "create", "update", "enable")
    ):
        return "extension"
    if any(n in name for n in ("bash", "shell", "terminal")):
        return "bash"
    if any(n in name for n in ("delete", "remove", "unlink")):
        return "file_delete"
    if any(n in name for n in ("glob", "grep", "ripgrep")):
        return "search"
    if any(
        n in name for n in ("fetch", "http", "web", "browse", "navigate", "curl", "wget", "search")
    ):
        return "network"
    if any(n in name for n in ("python", "code", "exec", "repl")):
        return "code"
    if any(n in name for n in ("read", "view", "open")):
        return "file_read"
    # write/edit last, many tool names contain these words innocuously
    if any(n in name for n in ("write", "edit", "create", "save", "insert")):
        return "file_write"

    return None


_TOOL_FAMILY = {
    "bash": "shell",
    "file_read": "file",
    "file_write": "file",
    "file_delete": "file",
    "file_editor": "file",
    "search": "search",
    "network": "network",
    "code": "code",
    "computer": "computer",
    "extension": "extension",
    "memory": "memory",
    "device": "device",
    "control_plane": "control_plane",
    "process": "process",
}


def _tool_family(category: Optional[str], tool_name: str) -> str:
    """Return the coarse mechanism family for a tool category.

    Known categories map to a stable family (shell/file/search/network/code/
    computer). Unrecognised tools get "unknown" so the fact is always present
    and policies can still target "this is some tool we don't model".
    """
    if category is None:
        return "unknown"
    return _TOOL_FAMILY.get(category, category)
