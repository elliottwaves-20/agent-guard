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


class CheckTests(unittest.TestCase):
    def run_check(self, fetch):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cip.check(fetch=fetch, now=NOW)
        return rc, out.getvalue()

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
