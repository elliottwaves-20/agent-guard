"""Offline registry, KEV and advisory lookups for the fast lane."""

import base64
import copy
import datetime as dt
import importlib
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from tests.test_lockcheck import FakeNet, github_advisory

TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parent / "scripts"))
fastlane = importlib.import_module("_fastlane")
lockcheck = importlib.import_module("_lockcheck")

FIXTURES = TEST_DIR / "fixtures" / "fastlane"
NPM_NAME = "@modelcontextprotocol/server-filesystem"
NPM_VERSION = "2.4.0"
NPM_OLD = "2.3.0"
NPM_ENCODED = "%40modelcontextprotocol%2fserver-filesystem"
NPM_PURL = "pkg:npm/%40modelcontextprotocol/server-filesystem"
NPM_REPO = "github.com/modelcontextprotocol/servers"
NPM_INTEGRITY = (
    "sha512-BoT8Gws5MsetfAey4vDyuzy8WYQES6mGYLSShuqSNGAC0X0NBV4p78/"
    "R78KfW4RkxtWz+zxhS9jwhzJrQUTt2Q=="
)
SLSA = "https://slsa.dev/provenance/v1"
PYPI_WHEEL = ("sigstore-4.5.1-py3-none-any.whl",
              "02e000197b34980f1d382741d6f83c2fecbcef7debf7304f36a5253f3c892cd9")
PYPI_SDIST = ("sigstore-4.5.1.tar.gz", "e" * 64)
PYPI_OLD = "4.5.0"
PYPI_OLD_WHEEL = ("sigstore-4.5.0-py3-none-any.whl", "a" * 64)
PYPI_METADATA = "https://pypi.org/pypi/sigstore/4.5.1/json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


def fixture(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def npm_attestation(version=NPM_VERSION):
    return f"https://registry.npmjs.org/-/npm/v1/attestations/{NPM_ENCODED}@{version}"


def npm_metadata(version=NPM_VERSION):
    return f"https://registry.npmjs.org/{NPM_ENCODED}/{version}"


def pypi_attestation(filename, version="4.5.1"):
    return f"https://pypi.org/integrity/sigstore/{version}/{filename}/provenance"


def npm_slsa_envelope(body):
    return next(att["bundle"]["dsseEnvelope"] for att in body["attestations"]
                if att["predicateType"] == SLSA)


def pypi_envelope(body):
    return body["attestation_bundles"][0]["attestations"][0]["envelope"]


def replace_subject(envelope, field, subject):
    statement = json.loads(base64.b64decode(envelope[field]))
    statement["subject"] = [subject]
    envelope[field] = base64.b64encode(json.dumps(statement).encode()).decode("ascii")


def pypi_files(*files):
    return {"urls": [{"filename": name, "digests": {"sha256": digest}}
                     for name, digest in files]}


def missing(host, response):
    return lockcheck.LookupFailed(str(fixture(response)), status=404, host=host)


class FakeFetch:
    def __init__(self, responses):
        self.responses = responses

    def __call__(self, url, payload=None):
        if url not in self.responses:
            raise AssertionError(f"unexpected request: {url}")
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response), None


class FastLaneFetchTests(unittest.TestCase):
    def npm_fetch(self, attestation):
        return FakeFetch({
            npm_metadata(): {"dist": {"integrity": NPM_INTEGRITY}},
            npm_attestation(): attestation,
        })

    def pypi_fetch(self, attestation, *files):
        return FakeFetch({
            PYPI_METADATA: pypi_files(*(files or (PYPI_WHEEL,))),
            pypi_attestation(PYPI_WHEEL[0]): attestation,
        })

    def test_scoped_subject_is_matched(self):
        fetch = self.npm_fetch(fixture("npm-attestations-200"))
        self.assertEqual(fastlane.npm_provenance(NPM_NAME, NPM_VERSION, fetch), NPM_REPO)

    def test_subject_digest_mismatch_fails(self):
        for subject_name, digest in (
            (f"{NPM_PURL}@{NPM_VERSION}", "a" * 128),
            ("pkg:npm/unrelated@2.4.0", base64.b64decode(NPM_INTEGRITY[7:]).hex()),
        ):
            with self.subTest(subject=subject_name):
                body = fixture("npm-attestations-200")
                replace_subject(npm_slsa_envelope(body), "payload",
                                {"name": subject_name, "digest": {"sha512": digest}})
                with self.assertRaises(lockcheck.LookupFailed):
                    fastlane.npm_provenance(NPM_NAME, NPM_VERSION, self.npm_fetch(body))

    def test_non_slsa_attestation_is_missing(self):
        body = fixture("npm-attestations-200")
        body["attestations"] = [att for att in body["attestations"]
                                if att["predicateType"] != SLSA]
        for response in (body, {"attestations": []}):
            with self.subTest(response=response is body):
                result = fastlane.npm_provenance(NPM_NAME, NPM_VERSION, self.npm_fetch(response))
                self.assertEqual(result, "missing")

    def test_npm_404_is_missing(self):
        fetch = self.npm_fetch(missing("registry.npmjs.org", "npm-attestations-404"))
        self.assertEqual(fastlane.npm_provenance(NPM_NAME, NPM_VERSION, fetch), "missing")

    def test_npm_429_and_500_fail(self):
        for status in (429, 500):
            with self.subTest(status=status):
                fetch = self.npm_fetch(lockcheck.LookupFailed("HTTP failure", status,
                                                             "registry.npmjs.org"))
                with self.assertRaises(lockcheck.LookupFailed):
                    fastlane.npm_provenance(NPM_NAME, NPM_VERSION, fetch)

    def test_npm_404_from_other_host_fails(self):
        for host in ("elsewhere.invalid", ""):
            with self.subTest(host=host):
                fetch = self.npm_fetch(missing(host, "npm-attestations-404"))
                with self.assertRaises(lockcheck.LookupFailed):
                    fastlane.npm_provenance(NPM_NAME, NPM_VERSION, fetch)

    def test_invalid_json_fails(self):
        broken_statement = fixture("npm-attestations-200")
        npm_slsa_envelope(broken_statement)["payload"] = base64.b64encode(b"{").decode("ascii")
        missing_predicate = fixture("npm-attestations-200")
        envelope = npm_slsa_envelope(missing_predicate)
        statement = json.loads(base64.b64decode(envelope["payload"]))
        del statement["predicateType"]
        envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode("ascii")
        for response in (lockcheck.LookupFailed("invalid response JSON"), {"attestations": {}},
                         {"attestations": [{}]}, broken_statement, missing_predicate):
            with self.subTest(response_type=type(response).__name__):
                with self.assertRaises(lockcheck.LookupFailed):
                    fastlane.npm_provenance(NPM_NAME, NPM_VERSION, self.npm_fetch(response))

    def test_pypi_publisher_key(self):
        body = fixture("pypi-provenance-200")
        body["attestation_bundles"][0]["publisher"]["repository"] = "Sigstore/Sigstore-Python"
        for project in ("sigstore", "Sigstore"):
            with self.subTest(project=project):
                result = fastlane.pypi_provenance(project, "4.5.1", (PYPI_WHEEL,),
                                                  self.pypi_fetch(body))
                self.assertEqual(result, "github:sigstore/sigstore-python")

    def test_pypi_mixed_publishers_fail(self):
        body = fixture("pypi-provenance-200")
        other = copy.deepcopy(body["attestation_bundles"][0])
        other["publisher"]["repository"] = "other/repository"
        body["attestation_bundles"].append(other)
        with self.assertRaises(lockcheck.LookupFailed):
            fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL,), self.pypi_fetch(body))

    def test_pypi_subject_of_other_file_fails(self):
        body = fixture("pypi-provenance-200")
        replace_subject(pypi_envelope(body), "statement",
                        {"name": PYPI_SDIST[0], "digest": {"sha256": PYPI_WHEEL[1]}})
        with self.assertRaises(lockcheck.LookupFailed):
            fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL,), self.pypi_fetch(body))

        for field, value in (("_type", None), ("_type", "invalid"), ("predicateType", None)):
            with self.subTest(field=field, value=value):
                body = fixture("pypi-provenance-200")
                envelope = pypi_envelope(body)
                statement = json.loads(base64.b64decode(envelope["statement"]))
                if value is None:
                    del statement[field]
                else:
                    statement[field] = value
                envelope["statement"] = base64.b64encode(json.dumps(statement).encode()).decode()
                with self.assertRaises(lockcheck.LookupFailed):
                    fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL,),
                                             self.pypi_fetch(body))

    def test_pypi_installed_version_needs_every_locked_file(self):
        sdist = fixture("pypi-provenance-200")
        replace_subject(pypi_envelope(sdist), "statement",
                        {"name": PYPI_SDIST[0], "digest": {"sha256": PYPI_SDIST[1]}})
        fetch = self.pypi_fetch(missing("pypi.org", "pypi-provenance-404"), PYPI_SDIST, PYPI_WHEEL)
        fetch.responses[pypi_attestation(PYPI_SDIST[0])] = sdist
        files = (PYPI_SDIST, PYPI_WHEEL)
        self.assertEqual(fastlane.pypi_provenance("sigstore", "4.5.1", files, fetch), "missing")

        fetch.responses[pypi_attestation(PYPI_SDIST[0])] = lockcheck.LookupFailed("unavailable", 500)
        with self.assertRaises(lockcheck.LookupFailed):
            fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL, PYPI_SDIST), fetch)

        mismatched_files = (PYPI_WHEEL, (PYPI_SDIST[0], "a" * 64))
        with self.assertRaises(lockcheck.LookupFailed):
            fastlane.pypi_provenance("sigstore", "4.5.1", mismatched_files, fetch)

    def pypi_fix_fetch(self):
        published = "2026-01-01T00:00:00Z"
        old_metadata = pypi_files(PYPI_OLD_WHEEL)["urls"]
        old_metadata[0]["upload_time_iso_8601"] = published
        advisory = github_advisory(name="sigstore", version_range=">= 4.5.0, < 4.5.1",
                                   fixed="4.5.1", ecosystem="pip")
        lock_fetch = FakeNet(
            pypi_files={
                ("sigstore", PYPI_OLD): old_metadata,
                ("sigstore", "4.5.1"): pypi_files(PYPI_WHEEL)["urls"],
            },
            ghsa={("reviewed", f"sigstore@{PYPI_OLD}"): [advisory]},
        )
        old_attestation = fixture("pypi-provenance-200")
        replace_subject(pypi_envelope(old_attestation), "statement", {
            "name": PYPI_OLD_WHEEL[0], "digest": {"sha256": PYPI_OLD_WHEEL[1]},
        })
        attestations = FakeFetch({
            KEV_URL: {"vulnerabilities": []},
            pypi_attestation(PYPI_OLD_WHEEL[0], PYPI_OLD): old_attestation,
            pypi_attestation(PYPI_WHEEL[0]): fixture("pypi-provenance-200"),
        })

        def fetch(url, payload=None):
            if url in attestations.responses:
                return attestations(url, payload)
            return lock_fetch(url, payload)

        return fetch

    def test_unknown_installed_pypi_hash_gives_no_verdict(self):
        entry = lockcheck.Entry("PyPI", "sigstore", PYPI_OLD,
                                hashes=(PYPI_OLD_WHEEL[1], "f" * 64))
        fetch = self.pypi_fix_fetch()
        advisories, failures = lockcheck.advisories_for([entry], fetch)
        self.assertEqual(failures, [])
        case = fastlane.gather(entry, advisories, kev=frozenset(), policy=fastlane.Policy(),
                               override="4.5.1", fetch=fetch)
        self.assertEqual(case["input"]["installed_provenance"], "failed")
        self.assertEqual(fastlane.decide(case)["action"], "no_verdict")

    def test_judge_tree_needs_exact_installed_pypi_version_for_provenance(self):
        entry = lockcheck.Entry("PyPI", "sigstore", PYPI_OLD, files=(PYPI_OLD_WHEEL,))
        previous = lockcheck.Entry("PyPI", "sigstore", "4.5.1", hashes=(PYPI_WHEEL[1],))
        verdict = fastlane.judge_tree(
            [entry], {}, receipts_root=TEST_DIR, kind="pypi", user_overrides={},
            policy=fastlane.Policy(), fetch=self.pypi_fix_fetch(),
            now=dt.datetime(2026, 1, 10, tzinfo=dt.timezone.utc),
            pypi_installed={lockcheck.entry_key(previous): previous},
        )
        self.assertEqual(verdict.code, 1)
        self.assertEqual([(item["action"], item["reason"]) for item in verdict.decisions],
                         [("report", "provenance_missing")])
        self.assertEqual(verdict.fixes, {})

    def test_pypi_404_is_missing(self):
        fetch = self.pypi_fetch(missing("pypi.org", "pypi-provenance-404"))
        self.assertEqual(fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL,), fetch),
                         "missing")
        fetch.responses[pypi_attestation(PYPI_WHEEL[0])] = missing(
            "other.invalid", "pypi-provenance-404"
        )
        with self.assertRaises(lockcheck.LookupFailed):
            fastlane.pypi_provenance("sigstore", "4.5.1", (PYPI_WHEEL,), fetch)

    def test_pure_wheel_detection(self):
        platform_wheel = ("sigstore-4.5.1-py3-none-win_amd64.whl", "b" * 64)
        second_pure_wheel = ("sigstore-4.5.1-py2-none-any.whl", "c" * 64)
        for files, expected in (
            ((PYPI_SDIST, platform_wheel, PYPI_WHEEL), (True, PYPI_WHEEL[1])),
            ((PYPI_WHEEL, second_pure_wheel), (False, "")),
            ((PYPI_SDIST, platform_wheel), (False, "")),
        ):
            with self.subTest(pure_wheel_expected=expected, files=files):
                fetch = FakeFetch({PYPI_METADATA: pypi_files(*files)})
                self.assertEqual(fastlane.pure_wheel("sigstore", "4.5.1", fetch), expected)

    def test_kev_unavailable_is_none(self):
        fetch = FakeFetch({KEV_URL: fixture("kev-sample")})
        self.assertEqual(fastlane.kev_cves(fetch), frozenset({"CVE-2026-129448", "CVE-2026-123890"}))
        for response in (lockcheck.LookupFailed("unavailable"), {}, {"vulnerabilities": [{}]}):
            fetch.responses[KEV_URL] = response
            with self.subTest(response_type=type(response).__name__):
                self.assertIsNone(fastlane.kev_cves(fetch))
        for count in (2, True):
            with self.subTest(count=count):
                fetch.responses[KEV_URL] = {
                    "count": count, "vulnerabilities": [{"cveID": "CVE-2026-129448"}],
                }
                self.assertIsNone(fastlane.kev_cves(fetch))

    def gather_npm(self, *, provenance_failure=False, advisory_failure=False):
        installed = lockcheck.Entry("npm", NPM_NAME, NPM_OLD)
        unrelated = lockcheck.Entry("npm", "unrelated", NPM_OLD)

        def advisory(entry, identifier, fixed):
            interval = {"lower": None, "upper": fixed, "lower_inclusive": True,
                        "upper_inclusive": False, "fixed": fixed}
            return lockcheck.Advisory(entry, identifier, "github-reviewed",
                                      severity="high", affected=(interval,))

        advisories = [advisory(installed, "GHSA-first", "2.3.1"),
                      advisory(installed, "GHSA-second", NPM_VERSION),
                      advisory(unrelated, "GHSA-unrelated", "3.0.0")]
        old_attestation = fixture("npm-attestations-200")
        replace_subject(npm_slsa_envelope(old_attestation), "payload",
                        {"name": f"{NPM_PURL}@{NPM_OLD}",
                         "digest": {"sha512": base64.b64decode(NPM_INTEGRITY[7:]).hex()}})
        npm = FakeFetch({
            npm_metadata(NPM_OLD): {"dist": {"integrity": NPM_INTEGRITY}},
            npm_metadata(): {"dist": {"integrity": NPM_INTEGRITY}},
            npm_attestation(NPM_OLD): old_attestation,
            npm_attestation(): (lockcheck.LookupFailed("unavailable", 500) if provenance_failure
                                else fixture("npm-attestations-200")),
        })
        advisory_calls = []

        def fetch(url, payload=None):
            if url == OSV_BATCH:
                self.assertEqual(payload, {"queries": [
                    {"package": {"name": NPM_NAME, "ecosystem": "npm"}, "version": NPM_VERSION}
                ]})
                advisory_calls.append("osv")
                if advisory_failure:
                    raise lockcheck.LookupFailed("unavailable", 500)
                return {"results": [{}]}, None
            if url.startswith("https://api.github.com/advisories?"):
                query = parse_qs(urlsplit(url).query)
                self.assertEqual(query["affects"], [f"{NPM_NAME}@{NPM_VERSION}"])
                advisory_calls.append(query["type"][0])
                return [], None
            return npm(url, payload)

        case = fastlane.gather(installed, advisories, kev=frozenset(), policy=fastlane.Policy(),
                               override=NPM_VERSION, fetch=fetch)
        self.assertCountEqual(advisory_calls, ["osv", "reviewed", "malware"])
        return case

    def test_gather_fetches_only_the_chosen_fix(self):
        case = self.gather_npm()
        self.assertEqual(case["kind"], "fast_lane")
        self.assertEqual(set(case["input"]["versions"]), {NPM_VERSION})
        self.assertCountEqual([adv["id"] for adv in case["input"]["advisories"]],
                              ["GHSA-first", "GHSA-second"])
        result = fastlane.decide(case)
        self.assertEqual((result["action"], result["version"], result["tier"]),
                         ("install", NPM_VERSION, "fast_lane"))

        self.check_pypi_gather()
        entry = lockcheck.Entry("npm", NPM_NAME, NPM_OLD)
        case = fastlane.gather(entry, [], kev=frozenset(), policy=fastlane.Policy(),
                               override=None, fetch=FakeFetch({}))
        self.assertEqual(fastlane.decide(case)["reason"], "not_triggered")

    def check_pypi_gather(self):
        old = "4.5.0"
        old_wheel = ("sigstore-4.5.0-py3-none-any.whl", "a" * 64)
        old_sdist = ("sigstore-4.5.0.tar.gz", "b" * 64)
        entry = lockcheck.Entry("PyPI", "sigstore", old)
        interval = {"lower": None, "upper": "4.5.1", "lower_inclusive": True,
                    "upper_inclusive": False, "fixed": "4.5.1"}
        advisories = [lockcheck.Advisory(entry, "GHSA-pypi", "github-reviewed",
                                         severity="high", affected=(interval,))]
        old_attestation = fixture("pypi-provenance-200")
        replace_subject(pypi_envelope(old_attestation), "statement",
                        {"name": old_wheel[0], "digest": {"sha256": old_wheel[1]}})
        registry = FakeFetch({
            "https://pypi.org/pypi/sigstore/4.5.0/json": pypi_files(old_wheel, old_sdist),
            PYPI_METADATA: pypi_files(PYPI_WHEEL, PYPI_SDIST),
            pypi_attestation(old_wheel[0], old): old_attestation,
            pypi_attestation(old_sdist[0], old): missing("pypi.org", "pypi-provenance-404"),
            pypi_attestation(PYPI_WHEEL[0]): fixture("pypi-provenance-200"),
        })

        def fetch(url, payload=None):
            if url == OSV_BATCH:
                self.assertEqual(payload, {"queries": [
                    {"package": {"name": "sigstore", "ecosystem": "PyPI"}, "version": "4.5.1"}
                ]})
                return {"results": [{}]}, None
            if url.startswith("https://api.github.com/advisories?"):
                self.assertEqual(parse_qs(urlsplit(url).query)["affects"], ["sigstore@4.5.1"])
                return [], None
            return registry(url, payload)

        case = fastlane.gather(entry, advisories, installed_files=(old_wheel, old_sdist),
                               kev=frozenset(), policy=fastlane.Policy(), override=None,
                               fetch=fetch)
        self.assertEqual(case["input"]["installed_provenance"], "missing")
        self.assertEqual(case["input"]["versions"]["4.5.1"], {
            "advisories": 0, "provenance": "github:sigstore/sigstore-python", "pure_wheel": True,
        })
        self.assertEqual(fastlane.decide(case)["reason"], "provenance_missing")

    def test_gather_marks_failures(self):
        for failure, field in (({"provenance_failure": True}, "provenance"),
                               ({"advisory_failure": True}, "advisories")):
            with self.subTest(field=field):
                case = self.gather_npm(**failure)
                self.assertEqual(case["input"]["versions"][NPM_VERSION][field], "failed")
                self.assertEqual(fastlane.decide(case)["action"], "no_verdict")

    def test_continuity_values(self):
        old_attestation = fixture("npm-attestations-200")
        replace_subject(npm_slsa_envelope(old_attestation), "payload",
                        {"name": f"{NPM_PURL}@{NPM_OLD}",
                         "digest": {"sha512": base64.b64decode(NPM_INTEGRITY[7:]).hex()}})
        fetch = self.npm_fetch(fixture("npm-attestations-200"))
        fetch.responses[npm_attestation(NPM_OLD)] = old_attestation
        fetch.responses[npm_metadata(NPM_OLD)] = {"dist": {"integrity": NPM_INTEGRITY}}
        for ecosystem, old in (("npm", None), ("PyPI", NPM_OLD)):
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual(fastlane.continuity(ecosystem, NPM_NAME, old, NPM_VERSION,
                                                     FakeFetch({})), "none")
        self.assertEqual(fastlane.continuity("npm", NPM_NAME, NPM_OLD, NPM_VERSION, fetch), "same")

        changed = fixture("npm-attestations-200")
        envelope = npm_slsa_envelope(changed)
        statement = json.loads(base64.b64decode(envelope["payload"]))
        workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        workflow["repository"] = "https://github.com/other/servers"
        envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode("ascii")
        for response, expected in (
            (changed, "different"),
            (missing("registry.npmjs.org", "npm-attestations-404"), "missing"),
            (lockcheck.LookupFailed("unavailable", 500), "failed"),
        ):
            with self.subTest(expected=expected):
                fetch.responses[npm_attestation()] = response
                self.assertEqual(fastlane.continuity("npm", NPM_NAME, NPM_OLD, NPM_VERSION, fetch),
                                 expected)
