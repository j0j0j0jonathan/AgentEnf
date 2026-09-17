# External evaluation

The thesis uses A3S-Bench from [ASEval / Agent3Sigma-Stage](https://github.com/antgroup/Agent3Sigma-Stage). Obtain the benchmark and its runner from that upstream repository. Its data and code have their own licenses and are not bundled here.

AgentEnf was connected to OpenClaw at the pre-tool and post-tool hooks. Runs with enforcement enabled consulted the proxy before execution. Control runs used the agent without that intervention. The study compared adversarial tasks and benign counterparts, repeated attack rollouts, and inspected completed effects alongside the benchmark's outcome labels. The thesis reports sample construction, revisions, prior exposure, approval settings and limitations.

For a new run:

1. Install the upstream benchmark and its documented container/runtime prerequisites.
2. Start AgentEnf with the intended policy and classifier configuration.
3. Install the OpenClaw plugin inside the agent environment and provide a reachable proxy URL, admin token, workspace roots and a stable session identity.
4. Check one harmless request and one blocked request before running a batch.
5. Run matching guarded and unguarded scenarios with the same agent configuration. Use a fresh proxy process and state directory when a run requires independent monitor history.
6. Keep infrastructure failures separate from policy interventions. Inspect the tool trace when a benchmark label does not establish whether the completing effect happened.

For the thesis's headless A3S configuration, `ENFGUARD_APPROVAL_MODE=warn` allowed approval requests to proceed with a warning. Only effective blocking counted as prevention. Interactive deployment should normally use `interactive` instead.

This repository supplies the current implementation and integration instructions. It does not publish a historical campaign snapshot or promise exact reproduction of the thesis's numerical results. No external benchmark is needed to run the system or its local regression tests.

## Development prompts

The [development corpus](../datasets/development-prompts/README.md) contains 1,269 unique prompts, including 971 attributed to model-generation sources. It includes expected historical verdicts and provenance, with an example generation brief. Its later consolidation split is not a historical held-out split. It is independent of the external A3S and AgentHazard datasets, which are obtained upstream.
