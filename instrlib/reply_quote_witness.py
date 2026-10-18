"""Conservative textual witnesses for the versioned reply guard.

A witness is prior textual presence, never authorization or proof of safety.
No code is executed. Unsupported equivalences retain no exception witness.
Ported without semantic changes from the frozen development implementation.
"""
import hashlib
import json
import math

from markdown_it import MarkdownIt

from instrlib.reply_evidence import reply_from_evidence


def code_units(reply):
    """Extract CommonMark inline/fenced/indented code; keep each unit separate."""
    units = []
    for token in MarkdownIt("commonmark").parse(reply):
        if token.type in {"fence", "code_block"}:
            # CommonMark represents a block's final line with a trailing newline.
            text = token.content.removesuffix("\n")
            if text:
                units.append(text)
        elif token.type == "inline":
            units.extend(child.content for child in token.children or []
                         if child.type == "code_inline" and child.content)
    return units


def _horizontal_space(text):
    """Collapse ASCII space/tab outside quoted/escaped text on one line only.

    Unlike shlex, this keeps quotation and escapes: a quoted glob is not made
    equivalent to an unquoted glob. Multiline code gets exact matching only.
    """
    if "\n" in text or "\r" in text:
        return None
    output, quote, index = [], None, 0
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'":
            if index + 1 == len(text):
                return None
            output.extend(text[index:index + 2])
            index += 2
            continue
        if char in {"'", '"', "`"}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        if char in " \t" and quote is None:
            if not output or output[-1] != " ":
                output.append(" ")
        else:
            output.append(char)
        index += 1
    return None if quote is not None else "".join(output).strip(" \t")


def prior_witness(unit, evidence):
    reply_from_evidence(evidence)  # Reject malformed/hidden-role envelopes.
    records = json.loads(evidence)["prior_context"]["records"]
    normalized = _horizontal_space(unit)
    for position, record in enumerate(records):
        prior = record["text"]
        candidates = [("whole_record_exact", prior),
                      *[("marked_code_exact", value) for value in code_units(prior)]]
        method = None
        for kind, candidate in candidates:
            if candidate == unit:
                method = kind
                break
            if normalized is not None and _horizontal_space(candidate) == normalized:
                method = kind.replace("exact", "horizontal_space")
                break
        if method is None and normalized:
            # Accept an explicitly present complete command at the end of one
            # line, e.g. "Earlier warning: rm ...". Never splice records/lines or
            # accept a prefix of a command with additional flags/arguments.
            for line in prior.splitlines():
                value = _horizontal_space(line)
                if value is None or not value.endswith(normalized):
                    continue
                start = len(value) - len(normalized)
                if start == 0 or value[start - 1] in " \t":
                    method = "complete_line_suffix_horizontal_space"
                    break
        if method:
            return {"record_position": position, "record_index": record.get("index"),
                    "method": method,
                    "record_sha256": hashlib.sha256(prior.encode()).hexdigest(),
                    "unit_sha256": hashlib.sha256(unit.encode()).hexdigest()}
    return None


def combine(evidence, full_scores, unit_scores, threshold=.5):
    """Add payload evidence and require a witness, retaining semantic coverage.

    The combination is monotone in restriction relative to the three-property
    rule: it can add Blocks, never turn an existing Block into Allow. Multiple
    dangerous code units do not establish one pre-existing complete procedure;
    for those, only an exact earlier copy of the whole reply supplies a witness.
    """
    reply = reply_from_evidence(evidence)
    units = code_units(reply)
    if set(full_scores) != {"dangerous_payload_present", "refusal_only", "prior_coverage"}:
        raise ValueError("Missing or unknown reply property")
    for score in [*full_scores.values(), *unit_scores, threshold]:
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Invalid property probability")
    if len(units) != len(unit_scores):
        raise ValueError("Need a score for every extracted code unit")
    dangerous = [(unit, score) for unit, score in zip(units, unit_scores, strict=True)
                 if score >= threshold]
    payload = full_scores["dangerous_payload_present"] >= threshold or bool(dangerous)
    witness = None
    if len(dangerous) == 1:
        witness = prior_witness(dangerous[0][0], evidence)
    elif payload:
        records = json.loads(evidence)["prior_context"]["records"]
        for position, record in enumerate(records):
            if record["text"] == reply:
                witness = {"record_position": position, "method": "whole_reply_exact"}
                break
    refusal = full_scores["refusal_only"] >= threshold
    coverage = full_scores["prior_coverage"] >= threshold
    exempt = refusal and coverage and witness is not None
    return {"label": int(payload and not exempt), "payload_present": payload,
            "refusal_only": refusal, "semantic_coverage": coverage,
            "witness": witness, "quoted_payload_scores": unit_scores,
            "dangerous_units": len(dangerous)}
