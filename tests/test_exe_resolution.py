"""Programs are found on PATH, never in the working directory (CWE-427).

Every test plants a real file in a real working directory (os.chdir into a
temp folder) and resolves against a real PATH string; nothing replaces
shutil.which, CreateProcess or Python.
"""
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import _exe  # noqa: E402

WINDOWS = os.name == "nt"
# CreateProcess appends only .exe to a bare name, so the child test needs a
# real executable: a copy of a system program that prints and exits.
SYSTEM_EXE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "hostname.exe"


def plant(folder, name: str) -> Path:
    """An executable `name` in `folder` that shutil.which accepts."""
    if WINDOWS:
        target = Path(folder) / f"{name}.bat"
        target.write_text("@echo planted\n", encoding="ascii")
    else:
        target = Path(folder) / name
        target.write_text("#!/bin/sh\necho planted\n", encoding="ascii")
        target.chmod(0o755)
    return target


class InWorkDir(unittest.TestCase):
    def setUp(self):
        self._old = os.getcwd()
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name).resolve()
        os.chdir(self.work)

    def tearDown(self):
        os.chdir(self._old)
        self._tmp.cleanup()


class WhichTests(InWorkDir):
    def test_a_name_only_in_the_working_directory_is_not_found_through_any_relative_entry(self):
        plant(self.work, "zzonlyhere")
        drive = os.path.splitdrive(str(self.work))[0]
        for entry in ("", ".", drive, "rel", os.path.join("rel", "sub"), os.curdir + os.sep):
            with self.subTest(entry=entry):
                self.assertIsNone(_exe.which("zzonlyhere", path=entry))
                self.assertIsNone(_exe.which("zzonlyhere", path=os.pathsep.join([entry, entry])))

    def test_the_working_directory_is_not_searched_before_the_path(self):
        planted = plant(self.work, "zzshadow")
        with tempfile.TemporaryDirectory() as real:
            genuine = plant(real, "zzshadow")
            found = _exe.which("zzshadow", path=os.pathsep.join(["", real]))
        self.assertIsNotNone(found)
        self.assertTrue(os.path.isabs(found))
        self.assertEqual(os.path.normcase(found), os.path.normcase(str(genuine)))
        self.assertNotEqual(os.path.normcase(found), os.path.normcase(str(planted)))

    def test_a_relative_command_with_a_folder_part_is_refused_and_an_absolute_one_kept(self):
        planted = plant(self.work, "zzrel")
        (self.work / "sub").mkdir()
        plant(self.work / "sub", "zzrel")
        relative = [os.curdir + os.sep + planted.name, os.path.join("sub", planted.name)]
        if WINDOWS:
            relative.append(os.path.splitdrive(str(self.work))[0] + planted.name)
        for cmd in relative:
            with self.subTest(cmd=cmd):
                self.assertTrue(shutil.which(cmd))   # the plain lookup would run it
                self.assertIsNone(_exe.which(cmd, path=""))
        self.assertEqual(os.path.normcase(_exe.which(str(planted), path="")),
                         os.path.normcase(str(planted)))

    def test_a_command_without_extension_is_found_through_pathext_on_every_python(self):
        # Before Python 3.12, shutil.which skipped PATHEXT for a name with a
        # folder part, so a lookup per PATH entry found nothing on Windows.
        with tempfile.TemporaryDirectory() as real:
            genuine = plant(real, "zzext")
            found = _exe.which("zzext", path=real)
            absolute = _exe.which(os.path.join(real, "zzext"), path="")
        self.assertEqual(os.path.normcase(found or ""), os.path.normcase(str(genuine)))
        self.assertEqual(os.path.normcase(absolute or ""), os.path.normcase(str(genuine)))

    def test_a_folder_named_like_the_program_is_skipped(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            (Path(first) / ("zzdir.bat" if WINDOWS else "zzdir")).mkdir()
            genuine = plant(second, "zzdir")
            found = _exe.which("zzdir", path=os.pathsep.join([first, second]))
        self.assertEqual(os.path.normcase(found or ""), os.path.normcase(str(genuine)))

    @unittest.skipUnless(WINDOWS, "a rooted path without a drive exists on Windows only")
    def test_a_rooted_entry_without_a_drive_is_not_absolute(self):
        # \Users\...\work means the working directory's drive, so it moves with
        # the working directory. Python 3.11 os.path.isabs accepts it.
        rooted = os.path.splitdrive(str(self.work))[1]
        plant(self.work, "zzrooted")
        self.assertEqual(_exe.safe_path(os.pathsep.join([rooted, r"\Windows"])), [])
        self.assertIsNone(_exe.which("zzrooted", path=rooted))
        self.assertIsNone(_exe.which(os.path.join(rooted, "zzrooted"), path=""))

    def test_an_empty_command_and_a_missing_program_give_none(self):
        plant(self.work, "")   # ".bat": an empty name plus an extension would match
        self.assertIsNone(_exe.which("", path=str(self.work)))
        self.assertIsNone(_exe.which(str(self.work) + os.sep, path=""))   # folder, no name
        self.assertIsNone(_exe.which("zz-not-installed-anywhere", path=str(self.work)))

    def test_the_process_path_is_used_by_default(self):
        with tempfile.TemporaryDirectory() as real:
            genuine = plant(real, "zzdefault")
            with patch.dict(os.environ, {"PATH": os.pathsep.join(["", real])}):
                found = _exe.which("zzdefault")
        self.assertEqual(os.path.normcase(found), os.path.normcase(str(genuine)))

    def test_without_a_path_variable_only_absolute_default_entries_count(self):
        plant(self.work, "zznopath")
        env = {k: v for k, v in os.environ.items() if k.upper() != "PATH"}
        with patch.dict(os.environ, env, clear=True):
            self.assertIsNone(_exe.which("zznopath"))
            self.assertEqual(_exe.safe_path(), [e for e in os.defpath.split(os.pathsep)
                                                if os.path.isabs(e)])


class HardenTests(InWorkDir):
    def test_harden_keeps_only_absolute_entries_in_order_and_sets_the_windows_switch(self):
        a, b = str(self.work / "a"), str(self.work / "b")
        drive = os.path.splitdrive(a)[0]
        environ = {"PATH": os.pathsep.join([a, "", drive, "rel", ".", b, ""])}
        _exe.harden_environ(environ)
        self.assertEqual(environ["PATH"], os.pathsep.join([a, b]))
        self.assertEqual(environ["NoDefaultCurrentDirectoryInExePath"], "1")

    def test_harden_changes_os_environ_by_default(self):
        a = str(self.work / "a")
        with patch.dict(os.environ, {"PATH": os.pathsep.join(["", a])}):
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            _exe.harden_environ()
            self.assertEqual(os.environ["PATH"], a)
            self.assertEqual(os.environ["NoDefaultCurrentDirectoryInExePath"], "1")

    @unittest.skipUnless(WINDOWS and SYSTEM_EXE.is_file(), "CreateProcess search is Windows only")
    def test_a_child_started_by_bare_name_never_comes_from_the_working_directory(self):
        shutil.copyfile(SYSTEM_EXE, self.work / "zzplanted.exe")
        child = (
            "import os, subprocess, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import _exe\n"
            "if sys.argv[2] == 'harden':\n"
            "    _exe.harden_environ()\n"
            "try:\n"
            "    print(subprocess.run(['zzplanted'], capture_output=True, text=True).returncode)\n"
            "except FileNotFoundError:\n"
            "    print('not found')\n")
        # The PATH this machine really has (with empty and drive-relative
        # entries) plus an empty one, so the test does not rely on the host.
        # os.environ upper-cases keys on Windows, so drop the switch by any case.
        env = {k: v for k, v in os.environ.items()
               if k.upper() != "NODEFAULTCURRENTDIRECTORYINEXEPATH"}
        env["PATH"] = os.pathsep.join(["", env.get("PATH", "")])

        def run(mode):
            return subprocess.run([sys.executable, "-I", "-c", child, str(SCRIPTS), mode],
                                  cwd=self.work, env=env, capture_output=True, text=True,
                                  timeout=60).stdout.strip()

        self.assertEqual(run("plain"), "0")          # the hole is real on this machine
        self.assertEqual(run("harden"), "not found")


class PathProperty(InWorkDir):
    """For random PATH lists, the result is None or the file in the first
    absolute entry that has it; never a hit through an empty or relative one."""

    def test_random_paths(self):
        name = "zzprop"
        plant(self.work, name)
        absolute = []
        for i in range(4):
            folder = self.work / f"abs{i}"
            folder.mkdir()
            absolute.append(str(folder))
        (self.work / "rel").mkdir()
        plant(self.work / "rel", name)
        drive = os.path.splitdrive(str(self.work))[0]
        relative = ["", ".", "rel", os.path.join(".", "rel"), os.curdir + os.sep]
        if drive:
            # Drive-relative, and rooted without a drive (the working
            # directory's drive): both move with the working directory.
            relative += [drive, os.path.splitdrive(str(self.work / "rel"))[1],
                         os.path.splitdrive(str(self.work))[1]]
        for seed in range(300):
            rng = random.Random(seed)
            with self.subTest(seed=seed):
                for folder in absolute:
                    target = plant(folder, name)
                    if rng.random() < 0.5:
                        target.unlink()
                pool = absolute + relative + [str(self.work)] * rng.randint(0, 1)
                entries = [rng.choice(pool) for _ in range(rng.randint(0, 8))]
                found = _exe.which(name, path=os.pathsep.join(entries))
                # Reference: the first entry with a drive (or a POSIX root)
                # whose folder holds the file; the order of PATHEXT decides
                # the name, and plant() makes exactly one name per folder.
                anchored = [e for e in entries if os.path.isabs(e)
                            and (not WINDOWS or os.path.splitdrive(e)[0])]
                expected = next((str(p) for e in anchored for p in Path(e).glob(name + "*")
                                 if p.is_file()), None)
                if found is None:
                    self.assertIsNone(expected, entries)
                    continue
                self.assertTrue(os.path.isabs(found), entries)
                self.assertIn(os.path.normcase(os.path.dirname(found)),
                              [os.path.normcase(e) for e in anchored], entries)
                self.assertEqual(os.path.normcase(found), os.path.normcase(expected), entries)


if __name__ == "__main__":
    unittest.main()
