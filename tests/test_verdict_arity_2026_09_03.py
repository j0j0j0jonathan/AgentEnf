"""Every verdict call in every shipped pack matches the signature's arity.

Why this exists. On 2026-09-03 a `substitution_retry` clause was added with
`Approve(t, "tool", "substitution_retry", "<reason>")`. `Block` and `Warn` take
four arguments and carry a reason string, but `Approve` takes three and has no
reason field. The mistake was invisible to the Python suite, all 3,178 tests
passed, and it only surfaced when `enfguard.exe` rejected the pack:

    SigError("arity of Approve is 3")

The OCaml type-check is the real authority, but it needs a binary that is not
present in every environment. This test is the cheap static guard that catches
the same class of error anywhere, so a pack cannot reach a launch script broken.

It parses the arity from `enfguard.sig` rather than hard-coding it, so if the
signature changes the test follows.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SIG = ROOT / "enfguard.sig"
PACKS = sorted(
    list((ROOT / "examples" / "presets").glob("*.yaml"))
    + list((ROOT / "tests" / "fixtures" / "policies").glob("*.yaml"))
)
VERDICTS = ("Block", "Warn", "Approve")


def signature_arities():
    """Map verdict name to declared argument count, read from enfguard.sig."""
    out = {}
    for line in SIG.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(\w+)\(([^)]*)\)", line.strip())
        if not m:
            continue
        name, args = m.group(1), m.group(2)
        if name in VERDICTS:
            out[name] = len([a for a in args.split(",") if a.strip()])
    return out


def split_top_level_args(argstr: str) -> int:
    """Count comma-separated arguments, ignoring commas inside string literals."""
    n, depth, in_str, esc = 1, 0, False, False
    for ch in argstr:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
        elif ch == '"':
            in_str = not in_str
        elif not in_str:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                n += 1
    return 0 if not argstr.strip() else n


def verdict_calls(mfotl: str):
    """Yield (verdict, arg_count, snippet) for each verdict application."""
    for m in re.finditer(r"\b(Block|Warn|Approve)\s*\(", mfotl):
        name = m.group(1)
        i = m.end()
        depth, start = 1, i
        while i < len(mfotl) and depth:
            c = mfotl[i]
            if c == '"':
                i += 1
                while i < len(mfotl) and mfotl[i] != '"':
                    i += 2 if mfotl[i] == "\\" else 1
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        args = mfotl[start:i - 1]
        yield name, split_top_level_args(args), mfotl[m.start():m.start() + 90]


def test_signature_declares_the_three_verdicts():
    ar = signature_arities()
    assert set(ar) == set(VERDICTS), ar
    # The asymmetry that caused the bug, pinned so a reader sees it.
    assert ar["Approve"] == 3, "Approve has no reason argument"
    assert ar["Block"] == 4 and ar["Warn"] == 4


@pytest.mark.parametrize("pack", PACKS, ids=lambda p: p.name)
def test_pack_verdict_arities_match_signature(pack):
    arity = signature_arities()
    try:
        doc = yaml.safe_load(pack.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        pytest.skip(f"unparseable yaml: {exc}")
    if not isinstance(doc, dict):
        pytest.skip("not a policy document")
    bad = []
    for pol in doc.get("policies") or []:
        mfotl = pol.get("mfotl") or ""
        for name, n, snippet in verdict_calls(mfotl):
            if n != arity[name]:
                bad.append(f"{pol.get('id')}: {name} called with {n}, "
                           f"signature says {arity[name]} :: {snippet}")
    assert not bad, "verdict arity mismatch:\n  " + "\n  ".join(bad)


def test_every_clause_has_balanced_parentheses():
    """Catch unbalanced parens statically, before the OCaml type-check.

    On 2026-09-07 the P1 split of the nine-way `destructive_impact` clause into
    six produced six clauses that each closed the inner OR group but never the
    group opened at `(PolicyActive`, leaving `ALWAYS(` dangling. enfguard.exe
    reported only "line 10 character 1 Error: No valid formula provided", which
    names neither the clause nor the real problem, and the whole pack failed to
    type-check.

    The OCaml check remains the authority, but it needs a macOS arm64 binary and
    so cannot run everywhere. This is the cheap portable guard, and unlike the
    binary it names the offending clause.
    """
    bad = []
    for pack in PACKS:
        try:
            doc = yaml.safe_load(pack.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        for pol in doc.get("policies") or []:
            mfotl = pol.get("mfotl") or ""
            for m in re.finditer(r'\{"([a-z0-9_]+)"\}\{(.*?)\n\s*\}', mfotl, re.S):
                name, body = m.group(1), m.group(2)
                delta = body.count("(") - body.count(")")
                if delta:
                    bad.append(f"{pack.name} :: {pol.get('id')} :: {name} "
                               f"has {delta:+d} unclosed parentheses")
    assert not bad, "unbalanced clause parentheses:\n  " + "\n  ".join(bad)
