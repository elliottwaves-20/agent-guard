"""Lockfile check for locked MCP installs (#48).

Every entry of a lockfile must come from the public registry, carry no
published advisory (OSV, GitHub reviewed and malware) and be at least
MIN_AGE_DAYS old. Anything that cannot be checked ends in no verdict.
"""
import datetime as dt
import importlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
lockcheck = importlib.import_module("_lockcheck")

NOW = dt.datetime(2026, 11, 22, 12, 0, tzinfo=dt.timezone.utc)
OLD = "2026-10-01T00:00:00.000Z"
NEW = "2026-11-20T00:00:00.000Z"


def npm_lock(packages):
    root = {"": {"name": "wrapper", "dependencies": {"srv": "1.0.0"}}}
    return {"lockfileVersion": 3, "packages": {**root, **packages}}


def npm_pkg(name, version, **extra):
    base = name.rsplit("/", 1)[-1]
    entry = {"version": version,
             "resolved": f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz",
             "integrity": f"sha512-{name}-{version}"}
    entry.update(extra)
    return entry


class FakeNet:
    """Answers the registry, OSV and GitHub requests from tables."""

    def __init__(self, osv=None, ghsa=None, npm_time=None, npm_integrity=None,
                 pypi_files=None, fail=None):
        self.osv = osv or {}
        self.ghsa = ghsa or {}
        self.npm_time = npm_time or {}
        self.npm_integrity = npm_integrity or {}
        self.pypi_files = pypi_files or {}
        self.fail = fail
        self.calls = []

    def __call__(self, url, payload=None):
        self.calls.append(url)
        if self.fail and self.fail in url:
            raise lockcheck.LookupFailed(f"simulated failure for {url}")
        if url.startswith(lockcheck.OSV_BATCH_URL):
            results = []
            for q in payload["queries"]:
                key = (q["package"]["name"], q["version"])
                ids = self.osv.get(key, [])
                results.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return {"results": results}, None
        if url.startswith(lockcheck.GITHUB_ADVISORIES_URL):
            query = url.split("?", 1)[1]
            params = dict(p.split("=", 1) for p in query.split("&"))
            kind = params["type"]
            affects = [a for a in params["affects"].replace("%40", "@").replace("%2F", "/").split("%2C")]
            hits = []
            for item in affects:
                for ghsa in self.ghsa.get((kind, item), []):
                    name = item.rpartition("@")[0]
                    hits.append({"ghsa_id": ghsa,
                                 "vulnerabilities": [{"package": {"name": name}}]})
            return hits, None
        if url.startswith(lockcheck.NPM_REGISTRY_URL):
            name = url[len(lockcheck.NPM_REGISTRY_URL):].replace("%2F", "/")
            times = self.npm_time.get(name)
            if times is None:
                raise lockcheck.LookupFailed("404")
            versions = {v: {"dist": {"integrity": self.npm_integrity.get((name, v), f"sha512-{name}-{v}")}}
                        for v in times}
            return {"time": times, "versions": versions}, None
        if url.startswith(lockcheck.PYPI_JSON_URL):
            name, version = url[len(lockcheck.PYPI_JSON_URL):].split("/")[:2]
            files = self.pypi_files.get((name, version))
            if files is None:
                raise lockcheck.LookupFailed("404")
            return {"urls": files}, None
        raise AssertionError(f"unexpected url {url}")


class NpmLockParsing(unittest.TestCase):
    def test_registry_entries_are_listed(self):
        lock = npm_lock({"node_modules/srv": npm_pkg("srv", "1.0.0"),
                         "node_modules/@scope/dep": npm_pkg("@scope/dep", "2.0.0"),
                         "node_modules/srv/node_modules/dep": npm_pkg("dep", "0.1.0")})
        entries = lockcheck.npm_lock_entries(lock)
        self.assertEqual(sorted((e.name, e.version) for e in entries),
                         [("@scope/dep", "2.0.0"), ("dep", "0.1.0"), ("srv", "1.0.0")])
        self.assertTrue(all(e.ecosystem == "npm" for e in entries))

    def test_aliased_entry_uses_its_real_name(self):
        entry = npm_pkg("real", "1.0.0")
        entry["name"] = "real"
        lock = npm_lock({"node_modules/alias": entry})
        self.assertEqual([(e.name, e.version) for e in lockcheck.npm_lock_entries(lock)],
                         [("real", "1.0.0")])

    def test_git_source_has_no_verdict(self):
        lock = npm_lock({"node_modules/srv": npm_pkg(
            "srv", "1.0.0", resolved="git+ssh://git@github.com/x/srv.git#abc")})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(lock)

    def test_lookalike_registry_host_has_no_verdict(self):
        lock = npm_lock({"node_modules/srv": npm_pkg(
            "srv", "1.0.0", resolved="https://registry.npmjs.org.evil.test/srv/-/srv-1.0.0.tgz")})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(lock)

    def test_missing_integrity_has_no_verdict(self):
        entry = npm_pkg("srv", "1.0.0")
        del entry["integrity"]
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(npm_lock({"node_modules/srv": entry}))

    def test_link_entry_has_no_verdict(self):
        lock = npm_lock({"node_modules/srv": {"resolved": "../srv", "link": True}})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(lock)

    def test_bundled_entry_has_no_verdict(self):
        lock = npm_lock({"node_modules/srv": npm_pkg("srv", "1.0.0"),
                         "node_modules/srv/node_modules/b": {"version": "1.0.0", "inBundle": True}})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(lock)

    def test_old_lockfile_version_has_no_verdict(self):
        lock = npm_lock({"node_modules/srv": npm_pkg("srv", "1.0.0")})
        lock["lockfileVersion"] = 1
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(lock)

    def test_empty_lock_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_lock_entries(npm_lock({}))


UV_LOCK = '''version = 1
requires-python = ">=3.12"

[options]
exclude-newer = "2026-11-15T00:00:00Z"

[[package]]
name = "wrapper"
version = "0.0.0"
source = { virtual = "." }

[[package]]
name = "srv"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/p/srv-1.0.0.tar.gz", hash = "sha256:aa", size = 1, upload-time = "2026-10-01T00:00:00Z" }
wheels = [
    { url = "https://files.pythonhosted.org/p/srv-1.0.0-py3-none-any.whl", hash = "sha256:bb", size = 1, upload-time = "2026-10-01T00:00:00Z" },
]
'''


class UvLockParsing(unittest.TestCase):
    def test_registry_entries_and_files_are_listed(self):
        entries = lockcheck.uv_lock_entries(UV_LOCK, root_name="wrapper")
        self.assertEqual([(e.ecosystem, e.name, e.version) for e in entries],
                         [("PyPI", "srv", "1.0.0")])
        self.assertEqual(sorted(entries[0].files),
                         [("srv-1.0.0-py3-none-any.whl", "bb"), ("srv-1.0.0.tar.gz", "aa")])

    def test_git_source_has_no_verdict(self):
        text = UV_LOCK.replace('source = { registry = "https://pypi.org/simple" }',
                               'source = { git = "https://github.com/x/srv?rev=abc#abc" }')
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries(text, root_name="wrapper")

    def test_other_index_has_no_verdict(self):
        text = UV_LOCK.replace("https://pypi.org/simple", "https://pypi.evil.test/simple")
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries(text, root_name="wrapper")

    def test_foreign_virtual_member_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries(UV_LOCK, root_name="other")

    def test_unreadable_lock_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries("not = [toml", root_name="wrapper")

    def test_package_without_files_has_no_verdict(self):
        text = UV_LOCK.split("sdist =")[0]
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries(text, root_name="wrapper")


def npm_entries():
    return lockcheck.npm_lock_entries(npm_lock({
        "node_modules/srv": npm_pkg("srv", "1.0.0"),
        "node_modules/@scope/dep": npm_pkg("@scope/dep", "2.0.0")}))


def clean_npm_net(**overrides):
    tables = dict(npm_time={"srv": {"1.0.0": OLD}, "@scope/dep": {"2.0.0": OLD}})
    tables.update(overrides)
    return FakeNet(**tables)


class Check(unittest.TestCase):
    def test_clean_tree_passes(self):
        net = clean_npm_net()
        result = lockcheck.check(npm_entries(), now=NOW, fetch=net)
        self.assertEqual(result.code, 0, result.lines)
        self.assertTrue(any("malware" in c for c in net.calls))
        self.assertTrue(any("reviewed" in c for c in net.calls))

    def test_osv_advisory_blocks(self):
        net = clean_npm_net(osv={("@scope/dep", "2.0.0"): ["GHSA-aaaa-bbbb-cccc"]})
        result = lockcheck.check(npm_entries(), now=NOW, fetch=net)
        self.assertEqual(result.code, 1)
        self.assertIn("GHSA-aaaa-bbbb-cccc", "\n".join(result.lines))

    def test_github_malware_advisory_blocks(self):
        net = clean_npm_net(ghsa={("malware", "srv@1.0.0"): ["GHSA-mal0-0000-0000"]})
        result = lockcheck.check(npm_entries(), now=NOW, fetch=net)
        self.assertEqual(result.code, 1)
        self.assertIn("GHSA-mal0-0000-0000", "\n".join(result.lines))

    def test_github_reviewed_advisory_blocks(self):
        net = clean_npm_net(ghsa={("reviewed", "@scope/dep@2.0.0"): ["GHSA-rev0-0000-0000"]})
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 1)

    def test_young_version_waits(self):
        net = clean_npm_net(npm_time={"srv": {"1.0.0": NEW}, "@scope/dep": {"2.0.0": OLD}})
        result = lockcheck.check(npm_entries(), now=NOW, fetch=net)
        self.assertEqual(result.code, 2)
        text = "\n".join(result.lines)
        self.assertIn("srv@1.0.0", text)
        self.assertIn("wait until 2026-11-27", text)

    def test_advisory_wins_over_waiting(self):
        net = clean_npm_net(npm_time={"srv": {"1.0.0": NEW}, "@scope/dep": {"2.0.0": OLD}},
                            osv={("@scope/dep", "2.0.0"): ["GHSA-aaaa-bbbb-cccc"]})
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 1)

    def test_unknown_publish_time_has_no_verdict(self):
        net = clean_npm_net(npm_time={"srv": {}, "@scope/dep": {"2.0.0": OLD}})
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 2)

    def test_integrity_mismatch_blocks(self):
        net = clean_npm_net(npm_integrity={("srv", "1.0.0"): "sha512-other"})
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 1)

    def test_lookup_failure_has_no_verdict(self):
        for part in ("osv.dev", "api.github.com", "registry.npmjs.org"):
            with self.subTest(part=part):
                net = clean_npm_net(fail=part)
                self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 2)

    def test_finding_wins_over_no_verdict(self):
        net = clean_npm_net(osv={("srv", "1.0.0"): ["MAL-2026-1"]}, fail="api.github.com")
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=net).code, 1)

    def test_osv_result_count_mismatch_has_no_verdict(self):
        net = clean_npm_net()
        real = net.__call__

        def short(url, payload=None):
            body, nxt = real(url, payload)
            if url.startswith(lockcheck.OSV_BATCH_URL):
                body = {"results": body["results"][:-1]}
            return body, nxt
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=short).code, 2)

    def test_github_pagination_is_followed(self):
        net = clean_npm_net()
        real = net.__call__
        pages = []

        def paged(url, payload=None):
            if url.startswith(lockcheck.GITHUB_ADVISORIES_URL) and "page2" not in url:
                pages.append(url)
                return [], url + "&page2"
            if "page2" in url:
                return [{"ghsa_id": "GHSA-page-2000-0000", "vulnerabilities": []}], None
            return real(url, payload)
        self.assertEqual(lockcheck.check(npm_entries(), now=NOW, fetch=paged).code, 1)

    def test_no_entries_has_no_verdict(self):
        self.assertEqual(lockcheck.check([], now=NOW, fetch=FakeNet()).code, 2)


class PypiCheck(unittest.TestCase):
    def entries(self):
        return lockcheck.uv_lock_entries(UV_LOCK, root_name="wrapper")

    def files(self, wheel_time=OLD, wheel_hash="bb"):
        return [{"filename": "srv-1.0.0.tar.gz", "upload_time_iso_8601": OLD,
                 "digests": {"sha256": "aa"}},
                {"filename": "srv-1.0.0-py3-none-any.whl", "upload_time_iso_8601": wheel_time,
                 "digests": {"sha256": wheel_hash}}]

    def test_clean_locked_files_pass(self):
        net = FakeNet(pypi_files={("srv", "1.0.0"): self.files()})
        self.assertEqual(lockcheck.check(self.entries(), now=NOW, fetch=net).code, 0)

    def test_young_locked_file_waits(self):
        net = FakeNet(pypi_files={("srv", "1.0.0"): self.files(wheel_time=NEW)})
        result = lockcheck.check(self.entries(), now=NOW, fetch=net)
        self.assertEqual(result.code, 2)
        self.assertIn("wait until", "\n".join(result.lines))

    def test_hash_mismatch_blocks(self):
        net = FakeNet(pypi_files={("srv", "1.0.0"): self.files(wheel_hash="zz")})
        self.assertEqual(lockcheck.check(self.entries(), now=NOW, fetch=net).code, 1)

    def test_locked_file_unknown_to_pypi_has_no_verdict(self):
        net = FakeNet(pypi_files={("srv", "1.0.0"): self.files()[:1]})
        self.assertEqual(lockcheck.check(self.entries(), now=NOW, fetch=net).code, 2)

    def test_github_uses_pip_ecosystem(self):
        net = FakeNet(pypi_files={("srv", "1.0.0"): self.files()})
        lockcheck.check(self.entries(), now=NOW, fetch=net)
        self.assertTrue(any("ecosystem=pip" in c for c in net.calls if "api.github.com" in c))


SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "f" * 40
GIT_PKG = f"""
[[package]]
name = "gitsrv"
version = "0.3.0"
source = {{ git = "https://github.com/Owner/Repo?rev={SHA}#{SHA}" }}
"""


class GitPinParsing(unittest.TestCase):
    pin = lockcheck.GitPin("gitsrv", "https://github.com/owner/repo", SHA)

    def entries(self, text, pin=pin):
        return lockcheck.uv_lock_entries(text, root_name="wrapper", git=pin)

    def test_expected_git_entry_is_accepted(self):
        entries = self.entries(UV_LOCK + GIT_PKG)
        self.assertEqual([e.name for e in entries], ["srv"])

    def test_git_entry_with_other_sha_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(UV_LOCK + GIT_PKG.replace(f"#{SHA}", f"#{OTHER_SHA}"))
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(UV_LOCK + GIT_PKG.replace(f"rev={SHA}", f"rev={OTHER_SHA}"))

    def test_git_entry_with_other_repo_has_no_verdict(self):
        for repo in ("https://github.com/owner/other", "https://gitlab.com/owner/repo",
                     "http://github.com/owner/repo", "https://github.com.evil.test/owner/repo"):
            with self.subTest(repo=repo):
                with self.assertRaises(lockcheck.NoVerdict):
                    self.entries(UV_LOCK + GIT_PKG.replace("https://github.com/Owner/Repo", repo))

    def test_git_entry_with_other_name_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(UV_LOCK + GIT_PKG.replace('name = "gitsrv"', 'name = "other"'))

    def test_git_entry_with_other_subdirectory_has_no_verdict(self):
        text = UV_LOCK + GIT_PKG.replace("?rev=", "?subdirectory=x&rev=")
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(text, lockcheck.GitPin("gitsrv", "https://github.com/owner/repo", SHA, "y"))
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(text)
        self.assertEqual(len(self.entries(
            text, lockcheck.GitPin("gitsrv", "https://github.com/owner/repo", SHA, "x"))), 1)

    def test_second_git_entry_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(UV_LOCK + GIT_PKG + GIT_PKG.replace('"gitsrv"', '"gitsrv2"'))

    def test_missing_git_entry_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            self.entries(UV_LOCK)

    def test_git_entry_without_expectation_has_no_verdict(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.uv_lock_entries(UV_LOCK + GIT_PKG, root_name="wrapper")

    def test_path_and_editable_entries_have_no_verdict(self):
        for source in ('{ path = "../x" }', '{ editable = "../x" }', '{ directory = "../x" }',
                       '{ url = "https://example.test/x.whl" }'):
            with self.subTest(source=source):
                text = UV_LOCK + GIT_PKG + (
                    '\n[[package]]\nname = "local"\nversion = "1.0.0"\n'
                    f"source = {source}\n")
                with self.assertRaises(lockcheck.NoVerdict):
                    self.entries(text)


class BuildConstraints(unittest.TestCase):
    def test_pinned_entries_reads_compile_output(self):
        text = "# generated\nsetuptools==80.9.0\n    # via -r -\n\nWheel==0.45.1\n"
        entries = lockcheck.pinned_entries(text)
        self.assertEqual([(e.name, e.version, e.all_files) for e in entries],
                         [("setuptools", "80.9.0", True), ("Wheel", "0.45.1", True)])

    def test_pinned_entries_refuses_ranges(self):
        for line in ("setuptools>=80", "setuptools", "x @ https://example.test/x.whl",
                     "-e ./x", "a==1.0; python_version<'3'"):
            with self.subTest(line=line):
                with self.assertRaises(lockcheck.NoVerdict):
                    lockcheck.pinned_entries(line + "\n")

    def test_pinned_entries_refuses_empty_output(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.pinned_entries("# nothing\n")

    def files(self, second_time=OLD):
        return [{"filename": "setuptools-80.9.0.tar.gz", "upload_time_iso_8601": OLD,
                 "digests": {"sha256": "aa"}},
                {"filename": "setuptools-80.9.0-py3-none-any.whl",
                 "upload_time_iso_8601": second_time, "digests": {"sha256": "bb"}}]

    def test_build_constraint_checks_every_file_of_the_version(self):
        entry = lockcheck.pinned_entries("setuptools==80.9.0\n")
        net = FakeNet(pypi_files={("setuptools", "80.9.0"): self.files()})
        self.assertEqual(lockcheck.check(entry, now=NOW, fetch=net).code, 0)
        net = FakeNet(pypi_files={("setuptools", "80.9.0"): self.files(second_time=NEW)})
        self.assertEqual(lockcheck.check(entry, now=NOW, fetch=net).code, 2)

    def test_build_constraint_without_files_on_pypi_has_no_verdict(self):
        entry = lockcheck.pinned_entries("setuptools==80.9.0\n")
        net = FakeNet(pypi_files={("setuptools", "80.9.0"): []})
        self.assertEqual(lockcheck.check(entry, now=NOW, fetch=net).code, 2)


class NpmTopLevel(unittest.TestCase):
    def lock(self, srv="1.0.0", dep="2.0.0", nested_dep=None):
        packages = {"node_modules/srv": npm_pkg("srv", srv),
                    "node_modules/dep": npm_pkg("dep", dep)}
        if nested_dep:
            packages["node_modules/srv/node_modules/dep"] = npm_pkg("dep", nested_dep)
        return npm_lock(packages)

    def test_top_level_integrity_is_returned(self):
        self.assertEqual(lockcheck.npm_top_level(self.lock(), "srv", "1.0.0", {}),
                         "sha512-srv-1.0.0")

    def test_top_level_must_match_the_pin(self):
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_top_level(self.lock(srv="1.0.1"), "srv", "1.0.0", {})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_top_level(self.lock(), "other", "1.0.0", {})

    def test_override_must_be_resolved_exactly(self):
        self.assertEqual(lockcheck.npm_top_level(self.lock(), "srv", "1.0.0", {"dep": "2.0.0"}),
                         "sha512-srv-1.0.0")
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_top_level(self.lock(nested_dep="1.0.0"), "srv", "1.0.0", {"dep": "2.0.0"})
        with self.assertRaises(lockcheck.NoVerdict):
            lockcheck.npm_top_level(self.lock(), "srv", "1.0.0", {"absent": "1.0.0"})


if __name__ == "__main__":
    unittest.main()
