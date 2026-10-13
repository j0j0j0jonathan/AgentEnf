# First enforced decision

This guide checks the HTTP gate, mapper, policy and real EnfGuard monitor together.
It requires no provider key and does not execute tools. It is an installation
check, not the full security pack or a test of classifier accuracy.

## 1. Install the prerequisites

Use macOS or Linux with Python 3.12+ and Node.js 22.12+. Native Windows is not
tested; use a Linux environment such as WSL. Install the separate monitor using
[monitor setup](monitor.md). Keep its executable's absolute path.

From a terminal:

```bash
git clone https://github.com/j0j0j0jonathan/AgentEnf.git
cd AgentEnf
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
npm --prefix frontend ci
npm --prefix frontend run build
```

If your compatible interpreter is called `python3` instead, use it for the venv
command. Confirm `python --version` inside the activated environment.

## 2. Terminal 1: prepare and start

Replace the monitor path below with the executable you built:

```bash
python scripts/quickstart.py init --monitor "/absolute/path/to/whyenf/_build/default/bin/enfguard.exe"
python scripts/quickstart.py start
```

Leave this terminal running. The helper creates `state/quickstart/` with a private
admin token, settings, an example workspace, monitor state and logs. That directory
is ignored by Git. The workspace contains only a README and an invented credential
file. It is a working directory, not an OS sandbox.

The server listens on `127.0.0.1:9000`. If that port is occupied, stop this process,
rerun `init` with `--port 9001`, then start again. Do not stop unrelated services.
Re-running `init` preserves existing example files and the token; it is not a reset.

## 3. Terminal 2: verify the decisions

Open another terminal, change to the same AgentEnf checkout and activate its venv:

```bash
source .venv/bin/activate
python scripts/quickstart.py check
python scripts/quickstart.py console
```

The helper reads the same saved token, so no token export or copying is needed.
Expected output (trace numbers vary):

```text
ALLOW: proposed read of README.md (trace ...)
BLOCK: proposed read of config/secrets.env (trace ...)
PASS: real monitor returned both expected decisions. No file reads were executed.
```

The check verifies that this port runs the expected quickstart YAML and that the
Block carries `quickstart_credential_read`, rather than accepting any failure as
a successful block. A runtime integration must additionally honour that decision.

In the console, open the two timepoints printed by the check. Look for
`ToolPlanned`, the path classification, and the named Block rule. The console
launcher opens an authenticated URL without printing its token. The UI stores the
token in browser storage and removes it from the address bar.

On a machine without browser launching, open `http://127.0.0.1:9000/enforcement`
in a browser on the same machine, adding `?admin_token=` followed by the contents
of `state/quickstart/admin-token` privately. Never share that URL or token.

Stop the proxy and its monitor with **Ctrl+C in Terminal 1**. To resume later,
run `start` again; no rebuild is needed unless code or frontend assets changed.

## 4. Choose the next step

| Goal | Configuration / guide |
|---|---|
| Verify installation offline | `examples/quickstart.yaml` (the helper always selects this) |
| Try a semantic temporal rule | `examples/decisions.yaml` and [Decisions guide](decisions.md) |
| Attach an existing assistant | [OpenClaw](../integrations/openclaw/README.md) or [NanoClaw](../integrations/nanoclaw/README.md) |
| Configure a broader deployment | `examples/presets/agentic-security.yaml`: 15 enabled groups, 79 labelled rules |
| Inspect the thesis evaluation configuration | `tests/fixtures/policies/eval_combined_graduated_a3s.yaml`: 18 enabled groups, 121 labelled rules |

The helper deliberately always runs the offline wiring check. For other policies,
stop it and use the direct launch instructions in [configuration](configuration.md).
A broad policy pack requires deployment-specific review; the evaluation fixture
is a reference, not an instruction to enable unattended approvals.

## Troubleshooting

| Symptom | Check |
|---|---|
| Cannot reach proxy | Terminal 1 must remain running; check its startup errors and configured port. |
| Health says monitor unhealthy | Check `ENFGUARD_BIN`, monitor compatibility and [Python/PyML troubleshooting](monitor.md). |
| Different policy error | Another service is on this port, or you started a non-quickstart YAML. |
| HTTP 401 | Use the same checkout and state directory in both terminals. The helper supplies the stored token. |
| Console missing or stale | Run `npm --prefix frontend ci` and `npm --prefix frontend run build`, then refresh. |
| Missing Python package | Activate `.venv` in each terminal and reinstall `pip install -e '.[dev]'`. |
| API key requested during this check | This offline helper does not require one. Check which launcher/configuration is running. |

For isolated testing, put `--state-dir /absolute/path/to/test-state` **before** the
subcommand on every invocation. Do not place that directory inside a public tree.
