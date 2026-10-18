"""The 7-day rule: which commit of a source may be staged at all.

GitHub records when each commit reached the branch (push, merge, force push);
unlike a commit's own date, that time cannot be set by whoever writes the
commit. Only a branch state that is at least COOLDOWN_DAYS old is staged.
"""
import datetime as dt
import importlib
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("AGENT_GUARD_NO_USER_CONFIG", "1")
staging = importlib.import_module("_staging")
url_resolver = importlib.import_module("_url_resolver")

NOW = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.timezone.utc)
HEAD, MID, OLD, OLDER = "1" * 40, "2" * 40, "3" * 40, "4" * 40


def activity(after, days_ago, before=OLDER, ref="refs/heads/main", kind="pr_merge"):
    ts = (NOW - dt.timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"after": after, "before": before, "timestamp": ts, "ref": ref, "activity_type": kind}


class Pages:
    def __init__(self, *pages):
        self.pages, self.urls = list(pages), []

    def __call__(self, url):
        self.urls.append(url)
        return self.pages.pop(0) if self.pages else []


def settled(fetch, head=HEAD):
    return staging.settled_ref("o/r", "main", head, now=NOW, fetch=fetch)


class SettledRefTests(unittest.TestCase):
    def test_newest_state_older_than_seven_days(self):
        fetch = Pages([activity(HEAD, 1), activity(MID, 4), activity(OLD, 9), activity(OLDER, 30)])
        self.assertEqual(settled(fetch)[0], OLD)
        self.assertIn("refs%2Fheads%2Fmain", fetch.urls[0])

    def test_head_older_than_seven_days_is_used(self):
        self.assertEqual(settled(Pages([activity(HEAD, 8)]))[0], HEAD)

    def test_no_branch_activity_means_head_is_old(self):
        self.assertEqual(settled(Pages([]))[0], HEAD)

    def test_all_recent_falls_back_to_the_state_before_the_oldest(self):
        fetch = Pages([activity(HEAD, 1, before=MID), activity(MID, 3, before=OLD)])
        self.assertEqual(settled(fetch)[0], OLD)

    def test_new_branch_without_an_old_state_stops(self):
        with self.assertRaises(staging.StageError):
            settled(Pages([activity(HEAD, 2, before="0" * 40)]))

    def test_order_of_entries_does_not_matter(self):
        fetch = Pages([activity(OLD, 9), activity(HEAD, 1), activity(MID, 4)])
        self.assertEqual(settled(fetch)[0], OLD)

    def test_later_pages_are_read(self):
        recent = [activity(HEAD, 1, before=MID)] * staging.ACTIVITY_PAGE
        fetch = Pages(recent, [activity(OLD, 10)])
        self.assertEqual(settled(fetch)[0], OLD)
        self.assertEqual(len(fetch.urls), 2)

    def test_cursor_pagination_follows_after_token_from_link_header(self):
        recent = [activity(HEAD, 1, before=MID)] * staging.ACTIVITY_PAGE
        seen_urls = []

        def cursor_fetch(url):
            seen_urls.append(url)
            if "after=cursor-page-2" in url:
                return ([activity(OLD, 10)], None)
            return (recent, "cursor-page-2")

        self.assertEqual(settled(cursor_fetch)[0], OLD)
        self.assertEqual(len(seen_urls), 2)
        self.assertNotIn("&page=", seen_urls[0])
        self.assertIn("after=cursor-page-2", seen_urls[1])

    def test_next_after_cursor_parses_github_link_header(self):
        header = (
            '<https://api.github.com/repositories/1/activity?ref=refs%2Fheads%2Fmain'
            '&per_page=100&after=Y3Vyc29yOnYyOpK7>; rel="next", '
            '<https://api.github.com/repositories/1/activity?ref=refs%2Fheads%2Fmain>; rel="first"'
        )
        self.assertEqual(staging._next_after_cursor(header), "Y3Vyc29yOnYyOpK7")
        self.assertIsNone(staging._next_after_cursor('<https://api.github.com/x>; rel="prev"'))
        self.assertIsNone(staging._next_after_cursor(""))

    def test_too_many_recent_changes_stop(self):
        recent = [activity(HEAD, 1, before=MID)] * staging.ACTIVITY_PAGE
        with self.assertRaises(staging.StageError):
            settled(Pages(*[recent] * (staging.ACTIVITY_MAX_PAGES + 1)))

    def test_invalid_entries_stop(self):
        for bad in ({"after": "x", "timestamp": "2026-01-01T00:00:00Z", "ref": "refs/heads/main"},
                    {"after": OLD, "timestamp": "yesterday", "ref": "refs/heads/main"}):
            with self.assertRaises(staging.StageError):
                settled(Pages([bad]))

    def test_api_error_stops(self):
        def fail(url):
            raise url_resolver.FetchError("rate limited")
        with self.assertRaises(staging.StageError):
            settled(fail)


class RemoteHeadTests(unittest.TestCase):
    def test_branch_and_commit_from_ls_remote(self):
        out = f"ref: refs/heads/main\tHEAD\n{HEAD}\tHEAD\n"
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=out, stderr="")

        self.assertEqual(staging.remote_head("o/r", run=run), ("main", HEAD))
        self.assertEqual(calls[0][-2:], ["https://github.com/o/r.git", "HEAD"])

    def test_failure_or_garbage_stops(self):
        for result in (SimpleNamespace(returncode=128, stdout="", stderr="not found"),
                       SimpleNamespace(returncode=0, stdout="garbage\n", stderr="")):
            with self.assertRaises(staging.StageError):
                staging.remote_head("o/r", run=lambda argv, r=result, **kw: r)


if __name__ == "__main__":
    unittest.main()
