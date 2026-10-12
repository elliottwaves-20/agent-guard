"""Make redirected console output UTF-8 (issue #3).

On Windows, Python falls back to cp1252 for stdout/stderr when they are redirected
to a file or pipe, so printing a non-ASCII character raises UnicodeEncodeError.
The CLI entry points call utf8_stdio() once from their __main__ block. Importing
this module changes nothing.
"""
from __future__ import annotations

import sys


def utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")
