#!/usr/bin/env python3
"""Prepare, launch and verify an isolated local AgentEnf wiring check.

Uses only the standard library. Checks submit proposals; they never execute tools.
No provider API key is required or persisted.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import webbrowser

ROOT = Path(__file__).resolve().parents[1]


def prepare(folder: Path, monitor: str, port: int) -> None:
    binary = Path(monitor).expanduser().resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Monitor must be an existing executable; see docs/monitor.md.")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_file = folder / "admin-token"
    if not token_file.exists():
        with open(token_file, "x", opener=lambda p, f: os.open(p, f, 0o600)) as f:
            f.write(secrets.token_urlsafe(32))
    token_file.chmod(0o600)
    workspace = folder / "workspace"
    (workspace / "config").mkdir(parents=True, exist_ok=True)
    for name, content in [
        ("README.md", "AgentEnf quickstart workspace.\n"),
        ("config/secrets.env", "DEMO_PASSWORD=not-a-real-password\n"),
    ]:
        path = workspace / name
        if not path.exists():
            path.write_text(content)
    (folder / "settings.json").write_text(
        json.dumps({"monitor": str(binary), "port": port}, indent=2)
    )
    print(f"Prepared {folder}\nToken saved privately; it is reused across terminals.")
    print("Next: python scripts/quickstart.py start (use the same --state-dir if customized).")


def settings(folder: Path):
    try:
        config = json.loads((folder / "settings.json").read_text())
        token = (folder / "admin-token").read_text().strip()
    except (OSError, ValueError) as exc:
        raise ValueError(
            "Run the init command first; use the same --state-dir in every terminal."
        ) from exc
    if not token:
        raise ValueError("The saved admin token is empty.")
    return config, token


def get_json(base, path, token, payload=None):
    request = Request(
        base + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={"X-Admin-Token": token, "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=15) as response:
        return json.load(response)


def check(folder: Path) -> None:
    config, token = settings(folder)
    base = f"http://127.0.0.1:{config['port']}"
    health = get_json(base, "/health", token)
    expected_policy = ROOT / "examples/quickstart.yaml"
    if health.get("ok") is not True:
        raise ValueError("Proxy answered, but the monitor is not healthy. Inspect its terminal.")
    if Path(health.get("yaml_file", "")).resolve() != expected_policy:
        raise ValueError("This port is serving a different policy. Stop it or choose another port.")
    sid = "quickstart-" + secrets.token_hex(6)
    cases = [("allow", "README.md"), ("block", "config/secrets.env")]
    for index, (expected, name) in enumerate(cases):
        result = get_json(
            base,
            "/v1/tool_execute",
            token,
            {
                "sid": sid,
                "call_id": f"{sid}-{index}",
                "tool_name": "file_read",
                "tool_input": {"path": str(folder / "workspace" / name)},
                "workspace_roots": [str(folder / "workspace")],
                "decision_schema_version": 1,
            },
        )
        if result.get("decision") != expected:
            raise ValueError(f"Expected {expected} for {name}, got {result.get('decision')!r}.")
        if expected == "block":
            verdicts = result.get("decision_trace", {}).get("policy_verdicts", [])
            if not any(v.get("category") == "quickstart_credential_read" for v in verdicts):
                raise ValueError("Block did not come from the expected quickstart rule.")
        print(f"{expected.upper()}: proposed read of {name} (trace {result.get('tid')})")
    print("PASS: real monitor returned both expected decisions. No file reads were executed.")
    print("Open the console and select these timepoints to inspect their events and verdicts.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=ROOT / "state/quickstart")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="prepare private token, settings and test workspace")
    init.add_argument("--monitor", required=True)
    init.add_argument("--port", type=int, default=9000)
    sub.add_parser("start", help="run the proxy and monitor in the foreground")
    sub.add_parser("check", help="verify Allow and Block without executing tools")
    sub.add_parser("console", help="open the authenticated console without printing its token")
    args = parser.parse_args()
    folder = args.state_dir.expanduser().resolve()
    try:
        if args.command == "init":
            if not 1 <= args.port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            prepare(folder, args.monitor, args.port)
            return
        config, token = settings(folder)
        if args.command == "check":
            check(folder)
        elif args.command == "console":
            url = f"http://127.0.0.1:{config['port']}/enforcement?" + urlencode(
                {"admin_token": token}
            )
            if not webbrowser.open(url):
                raise ValueError(
                    "No browser found. See the manual console instructions in docs/quickstart.md."
                )
            print("Opened the authenticated console.")
        else:
            env = dict(os.environ)
            env.update(
                ENFGUARD_ADMIN_TOKEN=token,
                ENFGUARD_BIN=config["monitor"],
                ENFGUARD_YAML=str(ROOT / "examples/quickstart.yaml"),
                ENFGUARD_STATE_DIR=str(folder / "monitor"),
                ENFGUARD_LOG_DIR=str(folder / "logs"),
                ENFGUARD_SESSIONS_DIR=str(folder / "monitor/sessions"),
                ENFGUARD_TIME_MODE="wall_seconds",
                ENFGUARD_TOOL_JUDGE="0",
                ENFGUARD_WS_HOST_ROOTS=str(folder / "workspace"),
                PROXY_PORT=str(config["port"]),
            )
            os.chdir(ROOT)
            os.execve(
                sys.executable,
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "proxy:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(config["port"]),
                    "--workers",
                    "1",
                ],
                env,
            )
    except HTTPError as exc:
        parser.exit(1, f"HTTP {exc.code}: check the saved token and proxy terminal.\n")
    except URLError:
        parser.exit(1, "Cannot reach the proxy. Start it in Terminal 1 and check the port.\n")
    except (ValueError, OSError) as exc:
        parser.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
