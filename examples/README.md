# AgentEnf Examples

The root `enfguard.yaml` is the small starter. This folder is the cookbook.
Copy snippets from here into `enfguard.yaml`, or start the proxy with a full
example file via:

```bash
export ENFGUARD_YAML=examples/presets/minimal-demo.yaml
python -m uvicorn proxy:app --host 127.0.0.1 --port 9000
```

## Presets

- `presets/minimal-demo.yaml` - compact tour of deterministic, semantic,
  approval, temporal, and outbound policy.
- `presets/boundary-demo.yaml` - isolates chat-in, chat-out, and an untrusted
  tool-result-to-action chain with one switch.
- `presets/memory-integrity-strict.yaml` - optional approval for every agent
  memory mutation, while poison-like writes remain blocked.
- `presets/agentic-security.yaml` - the full thirteen-category workstation-agent
  security pack used as the thesis case study.
- `presets/baseline_monitor.yaml` - minimal enforcement, maximum traceability.
- `presets/company_safe.yaml` - enterprise compliance and company data safety.
- `presets/personal_lockdown.yaml` - strong privacy and personal safety defaults.
- `presets/escalation_demo.yaml` - same predicate, different verdicts by safety level.
- `presets/cost_control.yaml` - token and model budget controls.
- `presets/privacy_shield.yaml` - personal-data protection before model calls.
- `presets/local_only.yaml` - force local/Ollama-style model usage.

## Building Blocks

- `switches.yaml` - examples for the global `audit | warn | enforce` mode plus int, boolean, float, and choice switches.
- `predicates.yaml` - builtin, Python, and LLM-judge predicates.
- `policies.yaml` - warn, block, approval, temporal, and model policies.
- `labeled_security_level.mfotl` - policy labels for newer EnfGuard binaries.

None of these files are loaded automatically.
