"""Bound classifier payloads without silently changing the evidence."""
import os
from functools import lru_cache


class EvidenceBudgetExceeded(ValueError):
    pass


@lru_cache(maxsize=8)
def _parse_limit(raw):
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        raise ValueError('ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES must be a positive integer') from None
    if limit <= 0:
        raise ValueError('ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES must be positive')
    return limit


def validate_evidence_budget():
    return _parse_limit(os.environ.get('ENFGUARD_CLASSIFIER_MAX_INPUT_BYTES', '65536'))


def check_evidence_budget(*parts):
    # UTF-8 bytes, not a token estimate. Config parsing is cached and startup validates it.
    limit = validate_evidence_budget()
    size = sum(len(part.encode('utf-8')) for part in parts)
    if size > limit:
        raise EvidenceBudgetExceeded(f'classifier_input_budget_exceeded: {size} > {limit} bytes')
