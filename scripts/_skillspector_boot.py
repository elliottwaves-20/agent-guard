#!/usr/bin/env python3
"""Launch SkillSpector inside its tool environment.

SkillSpector >= 2.11.1 reads SKILLSPECTOR_MAX_WORKFLOW_SECONDS natively.
The launcher preserves CLI arguments and environment. Its one change to the
scanner keeps OpenCode's OAuth plugins enabled (see _opencode_oauth.py).
UTF-8 is configured by the parent wrapper.
"""
import sys

import _opencode_oauth


def main() -> None:
    _opencode_oauth.keep_oauth_plugins()
    from skillspector.cli import app
    sys.argv[0] = "skillspector"
    app()


if __name__ == "__main__":
    main()
