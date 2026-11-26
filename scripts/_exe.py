"""Find programs on PATH without ever using the working directory (CWE-427).

On Windows, shutil.which looks in the working directory first unless
NoDefaultCurrentDirectoryInExePath is set, and both shutil.which and
CreateProcess treat an empty or drive-relative PATH entry (``""``, ``C:``)
as the working directory, so the variable alone is not enough. A planted
``uv.bat`` or ``docker.exe`` in the folder the user runs agent-guard from would
otherwise run with the scanner's rights. Here only anchored PATH entries count.
"""
from __future__ import annotations

import os

WINDOWS = os.name == "nt"
_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"


def anchored(path: str) -> bool:
    """True for a path that does not depend on the working directory: on
    Windows it needs a drive or UNC share and a root (``\\Windows`` alone means
    the working directory's drive, and Python before 3.13 calls it absolute)."""
    if not os.path.isabs(path):
        return False
    return not WINDOWS or bool(os.path.splitdrive(path)[0])


def safe_path(path: str | None = None) -> list[str]:
    """The anchored entries of `path` (default: this process's PATH)."""
    if path is None:
        path = os.environ.get("PATH", os.defpath)
    return [entry for entry in path.split(os.pathsep) if anchored(entry)]


def _names(cmd: str) -> list[str]:
    """File names `cmd` may have, in the order Windows tries them (PATHEXT);
    the name itself first only when it already ends in such an extension, as
    shutil.which does for executables since Python 3.12."""
    if not WINDOWS:
        return [cmd]
    exts = [ext for ext in (os.environ.get("PATHEXT") or _DEFAULT_PATHEXT).split(os.pathsep)
            if ext]
    names = [cmd + ext for ext in exts]
    if any(cmd.upper().endswith(ext.upper()) for ext in exts):
        names.insert(0, cmd)
    return names


def _find_in(folder: str, cmd: str) -> str | None:
    for name in _names(cmd):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def which(cmd: str, path: str | None = None) -> str | None:
    """Anchored path of `cmd` from an anchored PATH entry, else None.

    A command with a folder or drive part is taken only when it is anchored;
    a relative one would be resolved against the working directory.
    """
    if not cmd:
        return None
    folder, name = os.path.split(cmd)   # "C:x" splits into ("C:", "x")
    if folder:
        return _find_in(folder, name) if anchored(cmd) and name else None
    for entry in safe_path(path):
        found = _find_in(entry, cmd)
        if found:
            return found
    return None


def harden_environ(environ=None) -> None:
    """Make this process and every child resolve programs without the
    working directory: only anchored PATH entries, and on Windows
    NoDefaultCurrentDirectoryInExePath so CreateProcess and cmd.exe skip it."""
    if environ is None:
        environ = os.environ
    environ["PATH"] = os.pathsep.join(safe_path(environ.get("PATH", os.defpath)))
    environ["NoDefaultCurrentDirectoryInExePath"] = "1"
