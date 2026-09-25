#!/usr/bin/env python3
"""Launch Cisco mcp-scanner inside its tool environment, with one opt-in rule.

Cisco decides by model *name* whether a model is a reasoning model (only names
containing "gpt-5" get `max_completion_tokens` and `temperature=1`), and its
pinned LiteLLM does not know newer models. A reasoning model under any other
name is then rejected by the provider ("Unsupported parameter: 'max_tokens'").

When the active LLM profile declares `reasoning = true`, the wrapper sets
AGENT_GUARD_CISCO_REASONING=1 and starts Cisco through this launcher, which
applies Cisco's own reasoning rule to that model as well. Nothing else is
changed. If the hook this relies on is gone, the launcher refuses to run
instead of sending requests the provider would reject.
"""
import os
import sys


def install() -> None:
    if os.environ.get("AGENT_GUARD_CISCO_REASONING") != "1":
        return
    try:
        import mcpscanner.utils.llm_request_params as params_module
        original = params_module.apply_model_constraints
    except (ImportError, AttributeError):
        print("ERROR: Cisco mcp-scanner no longer exposes apply_model_constraints; "
              "the reasoning profile flag cannot be applied. Update agent-guard.",
              file=sys.stderr)
        sys.exit(2)

    def apply_model_constraints(model, params):
        original(model, params)
        if "max_tokens" in params:
            params["max_completion_tokens"] = params.pop("max_tokens")
        params["temperature"] = 1

    params_module.apply_model_constraints = apply_model_constraints


def main() -> None:
    install()
    from mcpscanner.cli import cli_entry_point
    sys.argv[0] = "mcp-scanner"
    cli_entry_point()


if __name__ == "__main__":
    main()
