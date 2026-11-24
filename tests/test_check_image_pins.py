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

    def test_sandbox_uv_is_checked_like_a_scanner(self):
        self.assertEqual(cip.SCANNERS["astral-sh/uv"][1], cip._pins.SANDBOX_UV)

    def test_runtime_lines_follow_the_sandbox_pins(self):
        self.assertEqual(cip.runtime_line("nodejs", "26.13.1"), "26")
        self.assertEqual(cip.runtime_line("python", "3.14.10"), "3.14")
        self.assertEqual(cip.RUNTIMES["nodejs"][1], cip._pins.SANDBOX_NODE)
        self.assertEqual(cip.RUNTIMES["python"][1], cip._pins.SANDBOX_PYTHON)


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
                     "set AGENT_GUARD_INTEGRATION=1 to check the endoflife.date contract")
class EndOfLifeContractTests(unittest.TestCase):
    def test_real_answer_has_the_fields_the_check_reads(self):
        for product, (_name, pinned) in cip.RUNTIMES.items():
            info = cip.fetch_line(product, cip.runtime_line(product, pinned))
            self.assertEqual(info["name"], cip.runtime_line(product, pinned))
            self.assertIn("isEol", info)
            self.assertRegex(info["eolFrom"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertIsNotNone(cip.parse_version(info["latest"]["name"]))
            self.assertRegex(info["latest"]["date"], r"^\d{4}-\d{2}-\d{2}$")

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


if __name__ == "__main__":
    unittest.main()
