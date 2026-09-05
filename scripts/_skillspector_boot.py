#!/usr/bin/env python3
"""
agent-guard bootstrap for SkillSpector: raise the aggregate workflow deadline.

SkillSpector (<= 2.11.0) hard-codes ``MAX_WORKFLOW_SECONDS = 60`` as the
deadline for one whole scan; the LLM analyzers stop with "shared runtime limit
reached" when it runs out and the report is only partial. With a coding-agent
CLI as provider every LLM call spawns a process, so even medium-sized skills
exhaust that budget. Upstream issue NVIDIA/SkillSpector#460 asks for an
override and PR #468 adds ``SKILLSPECTOR_MAX_WORKFLOW_SECONDS``; this shim
honours the same variable today and is harmless once upstream does too.

The wrapper runs this file with SkillSpector's own tool-environment Python:

    python _skillspector_boot.py scan <path> --format json --output report.json

Nothing else changes: the arguments are SkillSpector's, the scan is
SkillSpector's, only the budget default is widened before the CLI starts.
"""

import os
import sys


def apply_workflow_budget(seconds: float) -> bool:
    """Widen SkillSpector's default workflow budget to `seconds`.

    Patches ``skillspector.state.WorkflowResourceBudget`` so that budgets
    created without an explicit ``max_seconds`` use the new default. Must run
    before ``skillspector.cli`` is imported. Returns False when nothing was
    changed (non-positive value or upstream already allows at least that
    much)."""
    if seconds <= 0:
        return False
    import skillspector.state as state

    if float(getattr(state, "MAX_WORKFLOW_SECONDS", 0.0)) >= seconds:
        return False

    base = state.WorkflowResourceBudget

    class AgentGuardWorkflowBudget(base):  # type: ignore[misc,valid-type]
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("max_seconds", seconds)
            super().__init__(*args, **kwargs)

    AgentGuardWorkflowBudget.__name__ = base.__name__
    AgentGuardWorkflowBudget.__qualname__ = base.__qualname__
    state.WorkflowResourceBudget = AgentGuardWorkflowBudget
    state.MAX_WORKFLOW_SECONDS = seconds
    return True


def budget_from_env() -> float:
    raw = os.environ.get("SKILLSPECTOR_MAX_WORKFLOW_SECONDS", "").strip()
    if not raw:
        return 0.0
    try:
        return float(raw)
    except ValueError:
        return 0.0


def main() -> None:
    seconds = budget_from_env()
    if seconds > 0:
        apply_workflow_budget(seconds)
    from skillspector.cli import app

    sys.argv[0] = "skillspector"
    app()


if __name__ == "__main__":
    main()
