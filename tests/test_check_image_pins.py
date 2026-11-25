"""check_image_pins: report newer scanner releases and pick bump candidates."""
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
import check_image_pins as cip

NOW = datetime(2026, 11, 7, 20, 0, tzinfo=timezone.utc)


def rel(tag, days_ago, prerelease=False, draft=False):
    published = (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"tag_name": tag, "published_at": published,
            "prerelease": prerelease, "draft": draft}


class VersionTests(unittest.TestCase):
    def test_parse_version_accepts_plain_and_v_prefixed_tags(self):
        self.assertEqual(cip.parse_version("v3.10.0"), (3, 10, 0))
        self.assertEqual(cip.parse_version("1.28.0"), (1, 28, 0))

    def test_parse_version_rejects_prerelease_suffixes(self):
        self.assertIsNone(cip.parse_version("v3.0.0a2"))
        self.assertIsNone(cip.parse_version("latest"))


class NewerReleaseTests(unittest.TestCase):
    def test_reports_only_newer_stable_releases_with_their_eligible_date(self):
        releases = [rel("v3.10.0", 2), rel("v3.9.0", 10), rel("v3.2.0", 87),
                    rel("v3.1.0", 120), rel("v4.0.0a1", 1, prerelease=True),
                    rel("v3.11.0", 0, draft=True)]
        found = cip.newer_releases("3.2.0", releases, NOW)
        self.assertEqual([r["version"] for r in found], ["3.10.0", "3.9.0"])
        self.assertFalse(found[0]["eligible"])
        self.assertEqual(found[0]["eligible_from"], NOW - timedelta(days=2) + cip.MIN_AGE)
        self.assertTrue(found[1]["eligible"])

    def test_nothing_newer_is_empty(self):
        self.assertEqual(cip.newer_releases("3.2.0", [rel("v3.2.0", 87)], NOW), [])

    def test_unparsable_pinned_version_is_an_error_not_up_to_date(self):
        with self.assertRaises(ValueError):
            cip.newer_releases("latest", [rel("v3.2.0", 87)], NOW)

    def test_unparsable_publish_date_is_not_eligible(self):
        broken = {"tag_name": "v3.3.0", "published_at": None,
                  "prerelease": False, "draft": False}
        found = cip.newer_releases("3.2.0", [broken], NOW)
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0]["eligible"])


def line(name, latest, latest_days_ago, eol="2030-10-31", is_eol=False):
    """Shape of https://endoflife.date/api/v1/products/<p>/releases/<line> (result)."""
    date = (NOW - timedelta(days=latest_days_ago)).strftime("%Y-%m-%d")
    return {"name": name, "isEol": is_eol, "eolFrom": eol,
            "latest": {"name": latest, "date": date}}


def current_line(product, name):
    pinned = cip.RUNTIMES[product][1]
    return line(name, pinned, 30)


class CheckTests(unittest.TestCase):
    def run_check(self, fetch, fetch_line=current_line):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cip.check(fetch=fetch, fetch_line=fetch_line, now=NOW)
        return rc, out.getvalue()

    def test_runtime_line_extracts_node_major_and_python_major_minor(self):
        self.assertEqual(cip.runtime_line("nodejs", "26.13.1"), "26")
        self.assertEqual(cip.runtime_line("nodejs", "22.0.0"), "22")
        self.assertEqual(cip.runtime_line("python", "3.14.10"), "3.14")
        self.assertEqual(cip.runtime_line("python", "3.9.18"), "3.9")

    def test_sandbox_uv_reports_unprefixed_update_and_wait(self):
        def fetch_update(repo):
            if repo == "astral-sh/uv":
                return [rel("99.0.0", 10)]
            return [rel(cip.SCANNERS[repo][1], 30)]
        rc, out = self.run_check(fetch_update)
        self.assertEqual(rc, 1)
        self.assertIn("[UPDATE] uv (MCP sandbox) 99.0.0 can be pinned", out)

        def fetch_wait(repo):
            if repo == "astral-sh/uv":
                return [rel("99.0.1", 1)]
            return [rel(cip.SCANNERS[repo][1], 30)]
        rc, out = self.run_check(fetch_wait)
        self.assertEqual(rc, 1)
        self.assertIn("[WAIT] uv (MCP sandbox) 99.0.1 released", out)


    def test_up_to_date_exits_zero(self):
        def fetch(repo):
            return [rel("v" + cip.SCANNERS[repo][1], 30)]
        rc, out = self.run_check(fetch)
        self.assertEqual(rc, 0)
        self.assertIn("up to date", out)

    def test_newer_release_exits_one_and_names_it(self):
        def fetch(repo):
            if repo == "DataDog/guarddog":
                return [rel("v9.0.0", 10)]
            return []
        rc, out = self.run_check(fetch)
        self.assertEqual(rc, 1)
        self.assertIn("GuardDog 9.0.0", out)
        self.assertIn("can be pinned", out)

    def test_unexpected_api_answer_exits_two(self):
        rc, out = self.run_check(lambda repo: {"message": "API rate limit exceeded"})
        self.assertEqual(rc, 2)

    def test_release_without_date_waits(self):
        def fetch(repo):
            return [{"tag_name": "v99.0.0", "published_at": None,
                     "prerelease": False, "draft": False}]
        rc, out = self.run_check(fetch)
        self.assertEqual(rc, 1)
        self.assertIn("no readable release date", out)

    def test_fetch_error_exits_two(self):
        def fetch(repo):
            raise OSError("offline")
        rc, out = self.run_check(fetch)
        self.assertEqual(rc, 2)
        self.assertIn("could not check", out)


class RuntimeCheckTests(unittest.TestCase):
    def run_check(self, fetch_line):
        def fetch(repo):
            return [rel(cip.SCANNERS[repo][1], 30)]
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cip.check(fetch=fetch, fetch_line=fetch_line, now=NOW)
        return rc, out.getvalue()

    def test_current_patch_is_up_to_date(self):
        rc, out = self.run_check(current_line)
        self.assertEqual(rc, 0)
        self.assertIn(f"Python (MCP sandbox) {cip._pins.SANDBOX_PYTHON} is up to date", out)

    def test_new_patch_in_the_line_can_be_pinned_after_the_wait(self):
        def fetch_line(product, name):
            if product == "python":
                return line(name, "3.14.99", 10)
            return current_line(product, name)
        rc, out = self.run_check(fetch_line)
        self.assertEqual(rc, 1)
        self.assertIn("[UPDATE] Python (MCP sandbox) 3.14.99 can be pinned", out)

    def test_fresh_patch_waits(self):
        def fetch_line(product, name):
            if product == "nodejs":
                return line(name, "26.99.0", 1)
            return current_line(product, name)
        rc, out = self.run_check(fetch_line)
        self.assertEqual(rc, 1)
        self.assertIn("[WAIT] Node.js (MCP sandbox) 26.99.0", out)

    def test_end_of_life_line_is_reported(self):
        def fetch_line(product, name):
            if product == "nodejs":
                return line(name, cip._pins.SANDBOX_NODE, 30, eol="2026-04-30", is_eol=True)
            return current_line(product, name)
        rc, out = self.run_check(fetch_line)
        self.assertEqual(rc, 1)
        self.assertIn("[EOL] Node.js (MCP sandbox) line 26 reached end of life on 2026-04-30", out)

    def test_line_ending_soon_is_reported(self):
        soon = (NOW + timedelta(days=30)).strftime("%Y-%m-%d")
        def fetch_line(product, name):
            if product == "python":
                return line(name, cip._pins.SANDBOX_PYTHON, 30, eol=soon)
            return current_line(product, name)
        rc, out = self.run_check(fetch_line)
        self.assertEqual(rc, 1)
        self.assertIn(f"[EOL] Python (MCP sandbox) line 3.14 reaches end of life on {soon}", out)

    def test_unreadable_answer_exits_two(self):
        rc, out = self.run_check(lambda product, name: {"message": "not found"})
        self.assertEqual(rc, 2)
        self.assertIn("could not check", out)


@unittest.skipUnless(os.environ.get("AGENT_GUARD_INTEGRATION") == "1",
                     "set AGENT_GUARD_INTEGRATION=1 to check live API contracts")
class LivePinContractTests(unittest.TestCase):
    def test_endoflife_answer_has_the_fields_the_check_reads(self):
        for product, (_name, pinned) in cip.RUNTIMES.items():
            info = cip.fetch_line(product, cip.runtime_line(product, pinned))
            self.assertEqual(info["name"], cip.runtime_line(product, pinned))
            self.assertIn("isEol", info)
            self.assertRegex(info["eolFrom"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertIsNotNone(cip.parse_version(info["latest"]["name"]))
            self.assertRegex(info["latest"]["date"], r"^\d{4}-\d{2}-\d{2}$")

    def test_github_releases_match_contract_including_uv(self):
        now = datetime.now(timezone.utc)
        for repo, (_name, pinned) in cip.SCANNERS.items():
            with self.subTest(repo=repo):
                releases = cip.fetch_releases(repo)
                self.assertIsInstance(releases, list)
                self.assertGreater(len(releases), 0)
                stable = [r for r in releases if not r.get("draft") and not r.get("prerelease")]
                self.assertGreater(len(stable), 0)
                self.assertIsNotNone(cip.parse_version(stable[0].get("tag_name", "")))
                self.assertIsNotNone(cip._parse_time(stable[0].get("published_at")))
                newer = cip.newer_releases(pinned, releases, now)
                self.assertIsInstance(newer, list)

    def test_live_check_reports_every_pinned_target_without_error(self):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cip.check()
        text = out.getvalue()
        self.assertIn(rc, (0, 1), text)
        expected = ("Node.js (MCP sandbox)", "Python (MCP sandbox)",
                    "GuardDog", "malcontent", "uv (MCP sandbox)")
        lines = [line for line in text.splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), len(expected))
        for entry in lines:
            self.assertRegex(entry, r"^\[(OK|UPDATE|WAIT|EOL)\] ")
        for name in expected:
            self.assertIn(name, text)

class MalcontentCandidateTests(unittest.TestCase):
    def build(self, created_days_ago, digest, packages):
        return {"created": NOW - timedelta(days=created_days_ago),
                "digest": digest, "packages": packages}

    def test_picks_newest_minimal_build_old_enough_with_the_version(self):
        minimal = {"malcontent": "1.29.0-r0", "ca-certificates-bundle": "1"}
        dev = dict(minimal, busybox="1.37", **{"apk-tools": "2.14"})
        builds = [self.build(1, "sha256:new", minimal),
                  self.build(8, "sha256:dev", dev),
                  self.build(9, "sha256:good", minimal),
                  self.build(12, "sha256:older", minimal),
                  self.build(20, "sha256:oldversion", {"malcontent": "1.28.0-r0"})]
        got = cip.pick_malcontent_candidate(iter(builds), "1.29.0", NOW)
        self.assertEqual(got["digest"], "sha256:good")

    def test_stops_at_an_older_version(self):
        minimal = {"malcontent": "1.29.0-r0"}
        builds = [self.build(8, "sha256:old", {"malcontent": "1.28.0-r0"}),
                  self.build(9, "sha256:never", minimal)]
        self.assertIsNone(cip.pick_malcontent_candidate(iter(builds), "1.29.0", NOW))

    def test_none_when_no_build_qualifies(self):
        builds = [self.build(1, "sha256:new", {"malcontent": "1.29.0-r0"})]
        self.assertIsNone(cip.pick_malcontent_candidate(iter(builds), "1.29.0", NOW))


class FakeRegistry:
    def __init__(self, digests, broken=()):
        self._digests, self.broken = digests, set(broken)

    def digests(self):
        return self._digests

    def amd64(self, digest):
        if digest in self.broken:
            raise OSError("HTTP 429")
        return {"digest": digest}

    def created(self, manifest):
        return NOW - timedelta(days=int(manifest["digest"][-1]))

    def packages(self, manifest):
        return {"malcontent": "1.29.0-r0"}


class MalcontentBuildsTests(unittest.TestCase):
    def test_newest_first(self):
        reg = FakeRegistry([f"sha256:{i}" for i in (3, 1, 2)])
        got = [b["digest"] for b in cip.malcontent_builds(reg)]
        self.assertEqual(got, ["sha256:1", "sha256:2", "sha256:3"])

    def test_too_many_unreadable_builds_is_an_error(self):
        digests = [f"sha256:{i}" for i in range(1, 10)]
        reg = FakeRegistry(digests, broken=digests[:2])
        with self.assertRaises(RuntimeError):
            list(cip.malcontent_builds(reg))

    def test_no_readable_build_is_an_error(self):
        reg = FakeRegistry(["sha256:1"], broken=["sha256:1"])
        with self.assertRaises(RuntimeError):
            list(cip.malcontent_builds(reg))


class GitHubAuthHeaderTests(unittest.TestCase):
    """GITHUB_TOKEN / GH_TOKEN goes only to https://api.github.com and never redirects."""

    def _capture_urlopen(self, body, headers=None):
        import json
        seen = []

        class _Resp:
            def __init__(self):
                self.headers = headers or {}

            def read(self):
                return json.dumps(body).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, timeout=30):
            seen.append(req)
            return _Resp()

        return seen, fake_urlopen

    def test_github_api_callers_attach_unredirected_bearer_token(self):
        import importlib
        import urllib.request
        from unittest.mock import patch

        _url_resolver = importlib.import_module("_url_resolver")
        _staging = importlib.import_module("_staging")

        env = {"GITHUB_TOKEN": "  tok-primary\n", "GH_TOKEN": "tok-fallback"}
        with patch.dict(os.environ, env, clear=False):
            seen, fake_open = self._capture_urlopen([])
            with patch.object(urllib.request, "urlopen", side_effect=fake_open):
                cip.fetch_releases("astral-sh/uv")
                _url_resolver.http_json("https://api.github.com/repos/o/r")
                _staging._fetch_activity_page("https://api.github.com/repos/o/r/activity")
                _staging._fetch_repo("https://api.github.com/repos/o/r")

        self.assertEqual(len(seen), 4)
        for req in seen:
            with self.subTest(url=req.full_url):
                self.assertEqual(req.get_header("Authorization"), "Bearer tok-primary")
                self.assertNotIn("Authorization", req.headers)
                self.assertIn("Authorization", req.unredirected_hdrs)

    def test_gh_token_fallback_and_non_github_hosts_never_receive_token(self):
        import importlib
        import urllib.request
        from unittest.mock import patch

        _url_resolver = importlib.import_module("_url_resolver")
        env = {"GITHUB_TOKEN": "   ", "GH_TOKEN": " tok-gh "}
        with patch.dict(os.environ, env, clear=False):
            seen, fake_open = self._capture_urlopen({"result": {}})
            with patch.object(urllib.request, "urlopen", side_effect=fake_open):
                cip.fetch_line("nodejs", "26")
                _url_resolver.http_json("https://registry.npmjs.org/semver")
                _url_resolver.http_json("http://api.github.com/repos/o/r")
                _url_resolver.http_json("https://api.github.com:8443/repos/o/r")
                _url_resolver.http_json("https://user@api.github.com/repos/o/r")
                _url_resolver.http_json("https://api.github.com/repos/o/r")

        self.assertEqual(len(seen), 6)
        for req in seen[:5]:
            with self.subTest(url=req.full_url):
                self.assertIsNone(req.get_header("Authorization"))
        self.assertEqual(seen[5].get_header("Authorization"), "Bearer tok-gh")

        bad_req = urllib.request.Request("https://api.github.com:abc/repos/o/r")
        with patch.dict(os.environ, {"GITHUB_TOKEN": "tok-valid"}, clear=False):
            self.assertIsNone(_url_resolver.attach_github_auth(bad_req).get_header("Authorization"))

    def test_malformed_github_token_is_rejected_without_leaking_value(self):
        import importlib
        import urllib.request
        from unittest.mock import patch

        _url_resolver = importlib.import_module("_url_resolver")
        _staging = importlib.import_module("_staging")
        _lockcheck = importlib.import_module("_lockcheck")
        secret_part = "SECRET-MARKER-9988"
        for bad_token in (f"{secret_part}\r\nX-Injected: 1", f"{secret_part} tail", f"{secret_part}\u00e4"):
            with self.subTest(bad_token=repr(bad_token)):
                with patch.dict(os.environ, {"GITHUB_TOKEN": bad_token, "GH_TOKEN": ""}, clear=False):
                    with patch.object(urllib.request, "urlopen", side_effect=AssertionError("must fail before network")):
                        with patch.object(urllib.request, "build_opener", side_effect=AssertionError("must fail before network")):
                            with self.assertRaises(_url_resolver.FetchError) as url_err:
                                _url_resolver.http_json("https://api.github.com/repos/o/r")
                            self.assertNotIn(secret_part, str(url_err.exception))
                            with self.assertRaises(_url_resolver.FetchError) as stg_err:
                                _staging._fetch_repo("https://api.github.com/repos/o/r")
                            self.assertNotIn(secret_part, str(stg_err.exception))
                            with self.assertRaises(_lockcheck.LookupFailed) as lock_err:
                                _lockcheck.http_fetch("https://api.github.com/advisories?ecosystem=npm&affects=x")
                            self.assertNotIn(secret_part, str(lock_err.exception))
                            with self.assertRaises(ValueError) as cip_err:
                                cip.fetch_releases("astral-sh/uv")
                            self.assertNotIn(secret_part, str(cip_err.exception))

    def test_lockcheck_strips_github_token_whitespace_and_uses_unredirected_header(self):
        import importlib
        import urllib.request
        from unittest.mock import patch

        _lockcheck = importlib.import_module("_lockcheck")
        seen = []

        class _Resp:
            headers = {}

            def geturl(self):
                return "https://api.github.com/advisories"

            def getcode(self):
                return 200

            def read(self):
                return b"[]"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class _Opener:
            def open(self, req, timeout=60):
                seen.append(req)
                return _Resp()

        with patch.dict(os.environ, {"GITHUB_TOKEN": " tok-lock\r\n", "GH_TOKEN": ""}, clear=False):
            with patch.object(urllib.request, "build_opener", return_value=_Opener()):
                _lockcheck.http_fetch("https://api.github.com/advisories?ecosystem=npm&affects=x")
        self.assertEqual(seen[0].get_header("Authorization"), "Bearer tok-lock")
        self.assertNotIn("Authorization", seen[0].headers)
        self.assertIn("Authorization", seen[0].unredirected_hdrs)

        seen.clear()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "   ", "GH_TOKEN": ""}, clear=False):
            with patch.object(urllib.request, "build_opener", return_value=_Opener()):
                _lockcheck.http_fetch("https://api.github.com/advisories?ecosystem=npm&affects=x")
        self.assertIsNone(seen[0].get_header("Authorization"))



if __name__ == "__main__":
    unittest.main()
