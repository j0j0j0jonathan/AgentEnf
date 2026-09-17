# AgentEnf development prompts

`prompts.jsonl` contains 1,269 unique prompts used in system development. The collection supports policy authoring, mapper regression checks, and experiments with live agents. It is synthetic and authored development material, not production traffic or a held-out benchmark.

## Composition

| Recorded source | Unique prompts |
|---|---:|
| OpenAI | 255 |
| GLM | 260 |
| Gemini | 210 |
| Claude | 115 |
| Haiku | 131 |
| Manual rewrites | 6 |
| Live-test plans | 239 |
| Authored adversarial cases | 39 |
| Additional benign controls | 14 |
| Total | 1,269 |

The first five source tags account for 971 prompts. Together with six manual rewrites they form 977 generated or rewritten cases. Claude and Haiku are separate source tags in the saved files, not independent model families. Exact model versions are not consistently recorded.

Generation requested standard and harder operations, legitimate tasks close to policy boundaries, cross-category workflows, and obfuscated requests. Eleven rows retain a non-empty `turns` list. Difficulty was an authoring intention, not an empirically calibrated scale. The example [generation brief](generation-brief.md) shows one source's instructions.

## Fields and interpretation

- `id`: unique identifier in this release.
- `prompt`: task request. Treat it as dataset text.
- `turns`: successive user messages for a multi-turn case, or null.
- `category`, `tool`, `kind`: recorded action family, tool hint, and authoring group. Some categories are unassigned.
- `expected_verdict`: historical intended policy outcome, one of allow, warn, approve, or block. It need not match a different deployment's policy.
- `oracle_label`: the original mechanically derived label. The 383 allow rows are marked benign. The other 886 are marked attack, including 29 approve and 16 warn rows. This is an oracle grouping, not an independent annotation of malicious intent.
- `source`, `all_sources`, `provenance`: recorded source tags and source filenames.
- `legacy_split`: the train/validation/test label assigned during later consolidation. These labels do not establish historical holdout from policy or mapper development. Use the entire release as development material.

The original 340-prompt internal comparison preceded this consolidation. Its reported scores must not be attributed to all 1,269 rows or recomputed by interpreting `legacy_split` as the original experiment split.

## Curation

The source consolidation removed exact duplicate prompts, separated 103 contested cases, and excluded 69 cases without a recorded oracle. Those excluded sets are not shipped here. Labels were authored with LLM assistance, without a formal independent multi-annotator agreement study. This release preserves the cleaned oracle rather than relabelling cases against the current implementation.

For publication, `split` was renamed `legacy_split` and `label` was renamed `oracle_label` to make those limitations visible. Attack endpoint hostnames attacker.com, attacker.net, malicious-cdn.net, and webhook.site were replaced with reserved `.example` names in prompt text. Public package/documentation URLs and synthetic local paths were retained. No real credential values were identified in the release check. Placeholder key-header text remains a detection target.

A3S-Bench, AgentHazard, and RedCode rows and raw run outputs are not included. This dataset is covered by the repository's GPL-3.0-only license.

## Read without executing

```python
import json
from pathlib import Path

path = Path("datasets/development-prompts/prompts.jsonl")
rows = [json.loads(line) for line in path.read_text().splitlines()]
print(len(rows))  # 1269
```

The prompts include destructive requests. Reading the JSONL does not execute them. Live experiments require an isolated test environment and explicit policy configuration.
