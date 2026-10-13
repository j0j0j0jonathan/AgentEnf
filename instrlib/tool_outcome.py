"""Conservative runtime outcome evidence; never infer success from result prose."""
from typing import Any


def reported_outcome(body: dict[str, Any], *, blocked: bool = False) -> str:
    """A successful return is not proof of a committed external effect.

    Legacy result-only adapters remain `unknown`. Explicit errors override a
    claimed completion. Only trusted hook metadata can claim completion.
    """
    if blocked:
        return 'not_executed'
    execution = body.get('tool_execution')
    execution = execution if isinstance(execution, dict) else {}
    status = execution.get('outcome')
    code = body.get('exit_code')
    if status == 'failed' or (type(code) is int and code > 0):
        return 'failed'
    if status == 'running':
        return 'running'
    if status == 'not_executed' and execution.get('effect_executed') is False:
        return 'not_executed'
    if status == 'completed' and type(code) is int and code == 0:
        return 'runtime_reported_complete'
    return 'unknown'
