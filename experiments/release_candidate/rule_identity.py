"""Give candidate verdicts unambiguous rule identities without changing guards.

Historical packs stay frozen. Only literal verdict categories in labelled
IMPLIES:R consequences are renamed. Classify dimensions and policy ids are not.
"""
from collections import defaultdict
import re

LABEL = re.compile(r'\{"([^"\n]+)"\}\s*\{')
VERDICT = re.compile(r'(IMPLIES:R\s+(?:Block|Warn|Approve)\s*\(\s*\w+\s*,\s*"[^"]*"\s*,\s*")([^"\n]+)(")')


def entries(pack):
    for group in pack['policies']:
        text = group['mfotl']
        labels = list(LABEL.finditer(text))
        for i, label in enumerate(labels):
            start, end = label.start(), labels[i+1].start() if i+1 < len(labels) else len(text)
            verdicts = list(VERDICT.finditer(text, start, end))
            if not verdicts:
                # Suppression-only rules have no generated verdict category.
                if 'IMPLIES:R' in text[start:end]:
                    raise ValueError(f'Unrecognized consequence: {group["id"]}/{label[1]}')
                continue
            if len(verdicts) != 1:
                raise ValueError(f'Ambiguous consequence: {group["id"]}/{label[1]}')
            yield group, label[1], verdicts[0]


def uniquify(pack):
    rows = list(entries(pack))
    owners, label_owners = defaultdict(set), defaultdict(set)
    for group, label, match in rows:
        owner = (group['id'], label)
        owners[match[2]].add(owner)
        label_owners[label].add(owner)
    changes, edits = [], defaultdict(list)
    for group, label, match in rows:
        old = match[2]
        if len(owners[old]) <= 1:
            continue
        new = f'{group["id"]}__{label}' if len(label_owners[label]) > 1 else label
        edits[group['id']].append((match.start(2), match.end(2), new))
        changes.append(dict(policy_id=group['id'], rule_label=label, old_category=old, new_category=new))
    for group in pack['policies']:
        for start, end, new in reversed(edits[group['id']]):
            group['mfotl'] = group['mfotl'][:start] + new + group['mfotl'][end:]
    seen = {}
    for group, label, match in entries(pack):
        owner = (group['id'], label)
        if match[2] in seen and seen[match[2]] != owner:
            raise ValueError(f'Verdict identity collision: {match[2]}')
        seen[match[2]] = owner
    return changes
