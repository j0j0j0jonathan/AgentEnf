"""Precision of the project-document poisoning gate on a labelled corpus.

The 2026-09-03 change had the project-document gate consult
``_MEMPOISON_CONFIG_PUBLICATION_RE``, measured at 0/29 on the benign document
writes recorded in the A/B and isolated-memory cells. 29 is too thin to quote as
a precision result, so ``tests/benign_doc_corpus.py`` adds 20 authored documents
chosen to be hard: every one mentions a publication channel, a publication verb
or a live-configuration referent, and several mention all three in separate
sentences. A predicate that keys on any single ingredient will fail here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from instrlib import tool_mapper as tm  # noqa: E402

from benign_doc_corpus import BENIGN_DOCS, POISON_DOCS  # noqa: E402


def test_no_benign_document_is_classified_as_poisoning():
    tripped = sorted(
        name for name, body in BENIGN_DOCS.items()
        if tm._is_project_doc_poisoning_content(body)
    )
    assert not tripped, f"false positives: {tripped}"


def test_benign_documents_are_also_clean_on_the_memory_gate():
    """The memory gate is stricter. A benign doc written to a memory path must
    still be allowed, otherwise the corpus would only prove the weaker claim."""
    tripped = sorted(
        name for name, body in BENIGN_DOCS.items()
        if tm._is_memory_poisoning_content(body)
    )
    assert not tripped, f"false positives on the memory gate: {tripped}"


def test_every_poison_document_is_caught():
    missed = sorted(
        name for name, body in POISON_DOCS.items()
        if not tm._is_project_doc_poisoning_content(body)
    )
    assert not missed, f"missed poisoning documents: {missed}"


def test_corpus_is_actually_adversarial():
    """Guard against the corpus silently becoming easy.

    Every benign entry must contain at least one ingredient the predicate looks
    for. If someone replaces these with unrelated prose the precision claim stops
    meaning anything, and this test says so.
    """
    import re
    ingredient = re.compile(
        r"commit message|pr summar|pull request|slack|email|ticket"
        r"|settings\.ya?ml|server\.host|server\.port|logging\.file"
        r"|connection string|config(?:uration)?",
        re.IGNORECASE,
    )
    bland = sorted(n for n, b in BENIGN_DOCS.items() if not ingredient.search(b))
    assert not bland, f"corpus entries with no relevant ingredient: {bland}"
    assert len(BENIGN_DOCS) >= 20
