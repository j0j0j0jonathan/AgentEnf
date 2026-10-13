#!/usr/bin/env python3
"""Create an isolated, single-session OpenClaw profile for the local quickstart."""

import argparse
import json
from pathlib import Path
import secrets

from quickstart import ROOT, settings


def build_profile(folder, config, token, model, port):
    sid = "agentenf-" + secrets.token_hex(8)
    return {
        "agents": {
            "defaults": {
                "workspace": str(folder / "workspace"),
                "model": {"primary": "openai/" + model},
            }
        },
        "models": {
            "providers": {
                "openai": {
                    "baseUrl": f"http://127.0.0.1:{config['port']}/v1",
                    "apiKey": "${OPENAI_API_KEY}",
                    "api": "openai-responses",
                    "headers": {"x-session-id": sid},
                    "models": [{"id": model, "name": model}],
                }
            }
        },
        "gateway": {
            "mode": "local",
            "port": port,
            "bind": "loopback",
            "auth": {"mode": "token", "token": secrets.token_urlsafe(32)},
        },
        "plugins": {
            "allow": ["openai", "enfguard-gate"],
            "load": {"paths": [str(ROOT / "integrations/openclaw/enfguard-gate")]},
            "entries": {
                "enfguard-gate": {
                    "enabled": True,
                    "config": {
                        "enabled": True,
                        "apiUrl": f"http://127.0.0.1:{config['port']}",
                        "adminToken": token,
                        "sid": sid,
                        "failMode": "block",
                        "workspaceRoots": [str(folder / "workspace")],
                    },
                }
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=ROOT / "state/quickstart")
    parser.add_argument(
        "--model",
        required=True,
        help="OpenAI Responses model ID available to your account (without openai/ prefix)",
    )
    parser.add_argument("--gateway-port", type=int, default=18799)
    args = parser.parse_args()
    if not 1 <= args.gateway_port <= 65535:
        parser.error("Gateway port must be between 1 and 65535.")
    folder = args.state_dir.expanduser().resolve()
    try:
        config, token = settings(folder)
        profile = folder / "openclaw"
        profile.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = profile / "openclaw.json"
        import os

        with open(path, "x", opener=lambda p, f: os.open(p, f, 0o600)) as f:
            json.dump(
                build_profile(folder, config, token, args.model, args.gateway_port), f, indent=2
            )
    except FileExistsError:
        parser.exit(
            1,
            "Profile already exists; preserved it. Edit it deliberately or use a new --state-dir.\n",
        )
    except (ValueError, OSError) as exc:
        parser.exit(1, f"{exc}\n")
    print(
        f"Created {path}\nNo provider key saved. Use this profile for one conversation at a time."
    )


if __name__ == "__main__":
    main()
