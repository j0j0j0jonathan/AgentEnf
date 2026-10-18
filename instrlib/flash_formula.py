"""Constrained EnfFlash compilation transform; original formulas stay unchanged.

ONCE I (EXISTS p. evidence AND NOT (current = p)) becomes
EXISTS p. (ONCE I evidence) AND NOT (current = p).
Only top-level conjunctions and plain identifier inequalities are handled.
Unsupported constructs remain unchanged. This is not a general MFOTL optimizer.
"""

import json
import re

TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\#[^\n]*|[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]')
IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def tokens(text):
    return [m for m in TOKEN.finditer(text) if not m[0].startswith("#")]


def closing(ts, start, left="(", right=")"):
    depth = 0
    for i in range(start, len(ts)):
        if ts[i][0] == left:
            depth += 1
        elif ts[i][0] == right:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("Unbalanced input")


def conjunction(ts):
    """Return direct conjuncts; refuse a top-level non-conjunctive connective."""
    depth, start, parts = 0, 0, []
    for i, token in enumerate(ts):
        s = token[0]
        if s in ("(", "[", "{"):
            depth += 1
        elif s in (")", "]", "}"):
            depth -= 1
        elif depth == 0 and s in ("OR", "IMPLIES", "IFF", "SINCE", "UNTIL"):
            return None
        elif depth == 0 and s == "AND":
            parts.append(ts[start:i])
            start = i + 1
    parts.append(ts[start:])
    return parts


def rewrite(text):
    edits = []
    while True:
        ts = tokens(text)
        replacement = None
        # Innermost/rightmost first; tokenize again after each scoped change.
        for i in reversed(range(len(ts))):
            if ts[i][0] != "ONCE" or i + 2 >= len(ts) or ts[i + 1][0] != "[":
                continue
            ie = closing(ts, i + 1, "[", "]")
            op = ie + 1
            if op >= len(ts) or ts[op][0] != "(":
                continue
            end = closing(ts, op)
            body = ts[op + 1 : end]
            if not body or body[0][0] != "EXISTS":
                continue
            dot = next((j for j, t in enumerate(body) if t[0] == "."), None)
            if dot is None:
                continue
            declarations = [t[0] for t in body[1:dot]]
            if not declarations or any(
                (not IDENT.fullmatch(s)) if j % 2 == 0 else s != ","
                for j, s in enumerate(declarations)
            ):
                continue
            bound = set(declarations[::2])
            terms = conjunction(body[dot + 1 :])
            if not terms or any(not term for term in terms):
                continue
            moved, retained, outer = [], [], set()
            for term in terms:
                v = [x[0] for x in term]
                if (
                    len(v) == 6
                    and v[0:2] == ["NOT", "("]
                    and v[3] == "="
                    and v[5] == ")"
                    and IDENT.fullmatch(v[2])
                    and IDENT.fullmatch(v[4])
                    and ((v[2] in bound) != (v[4] in bound))
                ):
                    moved.append(term)
                    outer.add(v[4] if v[2] in bound else v[2])
                else:
                    retained.append(term)
            if not moved or not retained:
                continue
            if outer & {t[0] for term in retained for t in term}:
                continue  # cannot eliminate that outside dependency with this rewrite

            def original(part):
                return text[part[0].start() : part[-1].end()]

            interval = text[ts[i + 1].start() : ts[ie].end()]
            quantifier = text[body[0].start() : body[dot].end()]
            after = (
                "("
                + quantifier
                + " (ONCE "
                + interval
                + " ("
                + " AND ".join(original(t) for t in retained)
                + ")) AND "
                + " AND ".join(original(t) for t in moved)
                + ")"
            )
            start, stop = ts[i].start(), ts[end].end()
            before = text[start:stop]
            replacement = (start, stop, after)
            edits.append(
                {
                    "before": before,
                    "after": after,
                    "bound_variables": sorted(bound),
                    "outer_variables": sorted(outer),
                }
            )
            break
        if replacement is None:
            return text, edits
        start, stop, after = replacement
        text = text[:start] + after + text[stop:]


def without_labels(text):
    """Experimental metadata removal; preserve formula grouping and verdict args."""
    ts = tokens(text)
    edits, labels = [], []
    for i in range(len(ts) - 3):
        if (
            ts[i][0] == "{"
            and ts[i + 1][0].startswith('"')
            and ts[i + 2][0] == "}"
            and ts[i + 3][0] == "{"
        ):
            end = closing(ts, i + 3, "{", "}")
            edits.extend(
                [(ts[i].start(), ts[i + 3].end(), "("), (ts[end].start(), ts[end].end(), ")")]
            )
            labels.append(json.loads(ts[i + 1][0]))
    for start, stop, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[stop:]
    return text, labels
