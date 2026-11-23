"""Offline tests for the resolved lockfile verdict command."""

import base64
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import unquote, urlsplit

from tests.test_fastlane_fetch import (KEV_URL, SLSA, fixture, pypi_envelope,
                                      replace_subject)
from tests.test_lockcheck import NOW, OLD, FakeNet, github_advisory, npm_lock, npm_pkg
from tests.test_mcp_uv import uv_lock

import _lockcheck
import _mcp_locked
import _mcp_receipts
import check_lock

ROOT = Path(__file__).resolve().parents[1]
OLD_VERSION = "1.0.0"
FIX = "1.0.3"
HASH = "b" * 64
OTHER_HASH = "c" * 64
SDIST_HASH = "a" * 64
INTEGRITY = "sha512-" + base64.b64encode(b"x" * 64).decode("ascii")
THREE_DAYS = "2026-11-19T12:00:00Z"
ONE_DAY = "2026-11-21T12:00:00Z"


def package_file(name, version, digest, suffix="-py3-none-any.whl", time=ONE_DAY):
    return {"filename": f"{name.replace('-', '_')}-{version}{suffix}",
            "digests": {"sha256": digest}, "upload_time_iso_8601": time}


class OfflineNetwork(FakeNet):
    def __init__(self, *, npm_repositories=None, **kwargs):
        super().__init__(**kwargs)
        self.npm_repositories = npm_repositories or {}

    def __call__(self, url, payload=None):
        if self.fail and self.fail in url:
            return super().__call__(url, payload)
        if url == KEV_URL:
            self.calls.append(url)
            return {"vulnerabilities": []}, None
        path = unquote(urlsplit(url).path).strip("/")
        if path.startswith("-/npm/v1/attestations/"):
            self.calls.append(url)
            identity = path.removeprefix("-/npm/v1/attestations/")
            repository = self.npm_repositories.get(identity, "https://github.com/example/project")
            statement = {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": SLSA,
                "subject": [{"name": f"pkg:npm/{identity}", "digest": {"sha512": (b"x" * 64).hex()}}],
                "predicate": {"buildDefinition": {"externalParameters": {
                    "workflow": {"repository": repository}}}},
            }
            encoded = base64.b64encode(json.dumps(statement).encode()).decode("ascii")
            return {"attestations": [{"predicateType": SLSA,
                                      "bundle": {"dsseEnvelope": {"payload": encoded}}}]}, None
        if url.startswith(_lockcheck.NPM_REGISTRY_URL) and "/" in path and not path.startswith("@"):
            self.calls.append(url)
            return {"dist": {"integrity": INTEGRITY}}, None
        if path.startswith("integrity/"):
            self.calls.append(url)
            _, name, version, filename, _ = path.split("/")
            for artifact in self.pypi_files[(name, version)]:
                if artifact["filename"] == filename:
                    response = fixture("pypi-provenance-200")
                    replace_subject(pypi_envelope(response), "statement", {
                        "name": filename, "digest": artifact["digests"],
                    })
                    return response, None
            raise AssertionError(f"unexpected provenance request for {filename}")
        return super().__call__(url, payload)


def npm_network(*, names=("srv",), advisory=True, top_time=ONE_DAY, **network_options):
    times = {name: {OLD_VERSION: OLD, FIX: top_time} for name in names}
    integrity = {(name, version): INTEGRITY for name in names for version in times[name]}
    hits = {("reviewed", f"{name}@{OLD_VERSION}"): [github_advisory(name=name)]
            for name in names} if advisory else {}
    return OfflineNetwork(npm_time=times, npm_integrity=integrity, ghsa=hits, **network_options)


def pypi_network(*, old_files=None, fix_files=None):
    if old_files is None:
        old_files = [package_file("demo", OLD_VERSION, SDIST_HASH, time=OLD)]
    if fix_files is None:
        fix_files = [package_file("demo", FIX, HASH)]
    return OfflineNetwork(
        pypi_files={("demo", OLD_VERSION): old_files, ("demo", FIX): fix_files},
        ghsa={("reviewed", f"{name}@{OLD_VERSION}"): [
            github_advisory(name="demo", ecosystem="pip"),
        ] for name in ("demo", "Demo")},
    )


class CheckLockTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.receipts = self.root / "scans"

    def write(self, name, text, *, previous=False):
        directory = self.root / ("previous" if previous else "candidate")
        directory.mkdir(exist_ok=True)
        path = directory / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def npm(self, versions, *, previous=False):
        packages = {f"node_modules/{name}": npm_pkg(name, version, integrity=INTEGRITY)
                    for name, version in versions.items()}
        return self.write("package-lock.json", json.dumps(npm_lock(packages)), previous=previous)

    def requirements(self, version, hashes, *, previous=False, name="demo"):
        pin = f"{name}=={version}"
        tokens = [pin, *(f"--hash=sha256:{digest}" for digest in hashes)]
        return self.write("requirements.txt", " ".join(tokens), previous=previous)

    def receipt(self, kind="npm", package="srv", version=FIX, *, sha=HASH,
                integrity=INTEGRITY, verdict="SAFE"):
        _mcp_receipts.write_receipt(self.receipts, _mcp_receipts.Receipt(
            kind, package, version, sha, integrity, verdict, "2026-11-22", "0.0.0",
        ))

    def run_main(self, fetch, *args, with_receipts=True, as_json=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        options = list(args)
        if with_receipts:
            options += ["--receipts", str(self.receipts)]
        if as_json:
            options.append("--json")
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = check_lock.main(options, fetch=fetch, now=NOW)
        if not as_json:
            return code, stdout.getvalue() + stderr.getvalue()
        output = json.loads(stdout.getvalue())
        self.assertIsInstance(output, dict)
        self.assertEqual(code, output["code"])
        return code, output

    def test_clean_npm_lock_exits_0(self):
        path = self.npm({"srv": OLD_VERSION})
        code, result = self.run_main(npm_network(advisory=False), path)
        self.assertEqual(code, 0, result)

    def test_advisory_gives_decision(self):
        self.receipt()
        path = self.npm({"srv": OLD_VERSION})
        code, result = self.run_main(npm_network(), path)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["decisions"][0]["action"], "install")
        self.assertEqual(result["decisions"][0]["version"], FIX)
        self.assertEqual(result["advisories"][0]["kind"], "security")

    def test_file_report_wins_over_failed_young_fix_approval(self):
        path = self.npm({"srv": FIX, "dep": OLD_VERSION})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        fetch = npm_network(names=("srv", "dep"), advisory=False, fail=KEV_URL)
        fetch.ghsa[("reviewed", f"srv@{OLD_VERSION}")] = [github_advisory()]
        fetch.ghsa[("malware", f"dep@{OLD_VERSION}")] = [
            github_advisory("GHSA-malware", name="dep", fixed=None),
        ]
        code, result = self.run_main(fetch, path, "--previous", previous)
        self.assertEqual(code, 1, result)
        self.assertEqual([(item["package"], item["action"]) for item in result["decisions"]],
                         [("dep", "report")])
        self.assertTrue(any("KEV feed unavailable while checking installed versions" in line
                            for line in result["lines"]), result)

    def test_file_report_wins_over_receipt_access_failure(self):
        self.receipt()
        path = self.npm({"srv": FIX, "dep": OLD_VERSION})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        fetch = npm_network(names=("srv", "dep"))
        fetch.ghsa[("malware", f"dep@{OLD_VERSION}")] = [
            github_advisory("GHSA-malware", name="dep", fixed=None),
        ]
        young_fix_receipt = _mcp_receipts.receipt_path(self.receipts, "npm", "srv", FIX)
        is_file = Path.is_file

        def check_access(receipt_path):
            if receipt_path == young_fix_receipt:
                raise PermissionError("scan receipt access denied")
            return is_file(receipt_path)

        with mock.patch.object(Path, "is_file", autospec=True, side_effect=check_access):
            code, result = self.run_main(fetch, path, "--previous", previous)
        self.assertEqual(code, 1, result)
        self.assertEqual([(item["package"], item["action"]) for item in result["decisions"]],
                         [("dep", "report")])
        self.assertIn("NO VERDICT -- scan receipt access denied", result["lines"])

    def test_help_alone_exits_0(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag=flag):
                fetch = OfflineNetwork()
                code, output = self.run_main(fetch, flag, with_receipts=False, as_json=False)
                self.assertEqual(code, 0, output)
                self.assertIn("usage:", output)
                self.assertEqual(fetch.calls, [])

    def test_help_with_other_arguments_has_no_verdict(self):
        path = self.npm({"srv": OLD_VERSION})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        for options in ((path, "--previous", previous, "-h"), (path, "--previous", "-h"),
                        ("--invalid", "--help"), ("-h", path)):
            for as_json in (False, True):
                with self.subTest(options=options, as_json=as_json):
                    fetch = OfflineNetwork()
                    argv = [*options, "--json"] if as_json else list(options)
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        code = check_lock.main(argv, fetch=fetch, now=NOW)
                    if as_json:
                        result = json.loads(stdout.getvalue())
                        self.assertEqual(result["code"], 2, result)
                        self.assertTrue(any(line.startswith("NO VERDICT") for line in result["lines"]),
                                        result)
                        self.assertIn("usage:", stderr.getvalue())
                    else:
                        output = stdout.getvalue() + stderr.getvalue()
                        self.assertEqual(code, 2, output)
                        self.assertIn("usage:", output)
                        self.assertIn("NO VERDICT", output)
                    self.assertEqual(code, 2)
                    self.assertEqual(fetch.calls, [])

    def test_young_entry_without_receipt_needs_scan(self):
        path = self.npm({"srv": FIX, "dep": FIX})
        previous = self.npm({"srv": OLD_VERSION, "dep": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(names=("srv", "dep")), path,
                                     "--previous", previous)
        self.assertEqual(code, 2, result)
        self.assertCountEqual(result["needs_scan"], [
            {"kind": "npm", "package": name, "version": FIX} for name in ("srv", "dep")
        ])

    def test_young_fix_with_receipt_and_install_decision_passes(self):
        self.receipt()
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(), path, "--previous", previous)
        self.assertEqual(code, 0, result)
        self.assertEqual(result["young"], [])

    def test_young_fix_approval_fails_closed_on_unusable_evidence(self):
        self.receipt()
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        unmatched = npm_network()
        unmatched.ghsa[("reviewed", f"srv@{OLD_VERSION}")] = [
            github_advisory("GHSA-unmatched", name="another"),
        ]
        cases = (
            ("installed GitHub lookup", npm_network(fail=f"affects=srv%40{OLD_VERSION}&"),
             "previous advisory lookup failed"),
            ("unmatched installed advisory", unmatched, "cannot be matched to an installed version"),
            ("missing KEV feed", npm_network(fail=KEV_URL), "KEV feed unavailable"),
            ("installed provenance lookup",
             npm_network(fail=f"/attestations/srv@{OLD_VERSION}"),
             "the fast lane could not decide"),
        )
        for scenario, fetch, message in cases:
            with self.subTest(scenario=scenario):
                code, result = self.run_main(fetch, path, "--previous", previous)
                self.assertEqual(code, 2, result)
                self.assertTrue(any(message in line for line in result["lines"]), result)
                self.assertEqual(result["young"][0]["package"], "srv")
                self.assertEqual(result["needs_scan"], [])
                if scenario == "installed provenance lookup":
                    decision, = result["decisions"]
                    self.assertEqual((decision["installed"], decision["action"]),
                                     (OLD_VERSION, "no_verdict"))

    def test_no_fast_lane_makes_an_eligible_young_fix_wait(self):
        self.receipt()
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(), path, "--previous", previous, "--no-fast-lane")
        self.assertEqual(code, 2, result)
        self.assertEqual(result["young"][0]["package"], "srv")
        self.assertEqual(result["decisions"], [])

    def test_initial_github_lookup_failure_prevents_both_age_exemptions(self):
        self.receipt()
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        for top in ((), ("--top", "srv")):
            with self.subTest(top=top):
                options = (path, "--previous", previous, *top)
                code, result = self.run_main(npm_network(top_time=THREE_DAYS), *options)
                self.assertEqual(code, 0, result)

                network = npm_network(top_time=THREE_DAYS)
                failed = False

                def fetch(url, payload=None):
                    nonlocal failed
                    if (not failed and url.startswith(_lockcheck.GITHUB_ADVISORIES_URL)
                            and f"affects=srv%40{FIX}&" in url):
                        failed = True
                        raise _lockcheck.LookupFailed("simulated first FILE GitHub lookup failure")
                    return network(url, payload)

                code, result = self.run_main(fetch, *options)
                self.assertEqual(code, 2, result)
                self.assertTrue(failed)
                self.assertEqual(result["young"], [
                    {"package": "srv", "version": FIX, "wait_until": "2026-11-26"},
                ])
                self.assertEqual(result["decisions"], [])

    def test_fix_pulling_one_day_old_new_dependency_waits(self):
        self.receipt()
        path = self.npm({"srv": FIX, "dep": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(names=("srv", "dep")), path,
                                     "--previous", previous)
        self.assertEqual(code, 2, result)
        self.assertEqual([entry["package"] for entry in result["young"]], ["dep"])

    def test_young_fix_receipt_must_match_npm_integrity(self):
        self.receipt(integrity="sha512-other")
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(), path, "--previous", previous)
        self.assertEqual(code, 2, result)

    def test_block_receipt_for_eligible_fix_is_a_finding(self):
        self.receipt(verdict="BLOCK")
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(npm_network(), path, "--previous", previous)
        self.assertEqual(code, 1, result)

    def test_receipt_alone_never_allows_a_young_version(self):
        self.receipt()
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        for options in ((), ("--previous", previous)):
            with self.subTest(options=options):
                code, result = self.run_main(npm_network(advisory=False), path, *options)
                self.assertEqual(code, 2, result)
                self.assertEqual(result["young"][0]["package"], "srv")
                self.assertEqual(result["needs_scan"], [])

    def test_requirements_need_one_hash_per_fix(self):
        self.receipt("pypi", "demo")
        path = self.requirements(FIX, (HASH, OTHER_HASH))
        previous = self.requirements(OLD_VERSION, (SDIST_HASH,), previous=True)
        fetch = pypi_network(fix_files=[package_file("demo", FIX, HASH),
                                       package_file("demo", FIX, OTHER_HASH, ".tar.gz")])
        code, result = self.run_main(fetch, path, "--previous", previous)
        self.assertEqual(code, 2, result)
        self.assertEqual(result["needs_scan"], [])

    def test_requirements_fix_hash_must_match_receipt(self):
        self.receipt("pypi", "demo", sha=OTHER_HASH)
        path = self.requirements(FIX, (HASH,))
        previous = self.requirements(OLD_VERSION, (SDIST_HASH,), previous=True)
        code, result = self.run_main(pypi_network(), path, "--previous", previous)
        self.assertEqual(code, 2, result)
        self.assertTrue(any("fast lane fix needs exactly the hash in the SAFE receipt" in line
                            for line in result["lines"]), result)
        self.assertEqual(result["needs_scan"], [])

    def test_requirements_without_hashes_have_no_verdict(self):
        path = self.requirements(FIX, ())
        fetch = pypi_network()
        code, result = self.run_main(fetch, path)
        self.assertEqual(code, 2, result)
        self.assertEqual(fetch.calls, [])

    def test_uv_lock_needs_root_name(self):
        path = self.write("uv.lock", uv_lock("wrapper", "demo", FIX))
        fetch = pypi_network()
        code, result = self.run_main(fetch, path)
        self.assertEqual(code, 2, result)
        self.assertEqual(fetch.calls, [])

    def test_s1_needs_previous(self):
        path = self.npm({"srv": FIX})
        code, result = self.run_main(npm_network(top_time=THREE_DAYS), path, "--top", "srv")
        self.assertEqual(code, 2, result)
        self.assertEqual(result["young"][0]["package"], "srv")

    def test_s1_only_for_the_named_top(self):
        fetch = npm_network(names=("srv", "dep"), advisory=False, top_time=THREE_DAYS)
        path = self.npm({"srv": FIX, "dep": FIX})
        previous = self.npm({"srv": OLD_VERSION, "dep": OLD_VERSION}, previous=True)
        code, result = self.run_main(fetch, path, "--previous", previous, "--top", "srv")
        self.assertEqual(code, 2, result)
        self.assertEqual([entry["package"] for entry in result["young"]], ["dep"])

    def test_s1_without_top_is_s2(self):
        fetch = npm_network(advisory=False, top_time=THREE_DAYS)
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        code, result = self.run_main(fetch, path, "--previous", previous)
        self.assertEqual(code, 2, result)
        self.assertEqual(result["young"][0]["package"], "srv")

    def test_s1_same_repository_uses_trusted_age_limit(self):
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        for published, expected_code, wait_until in (
            (THREE_DAYS, 0, None),
            (ONE_DAY, 2, "2026-11-23"),
        ):
            with self.subTest(published=published):
                fetch = npm_network(advisory=False, top_time=published)
                code, result = self.run_main(fetch, path, "--previous", previous, "--top", "srv")
                self.assertEqual(code, expected_code, result)
                expected = ([{"package": "srv", "version": FIX, "wait_until": wait_until}]
                            if wait_until else [])
                self.assertEqual(result["young"], expected)

    def test_top_from_different_repository_uses_s2_age_limit(self):
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        fetch = npm_network(advisory=False, top_time=THREE_DAYS,
                            npm_repositories={f"srv@{FIX}": "https://github.com/other/project"})
        code, result = self.run_main(fetch, path, "--previous", previous, "--top", "srv")
        self.assertEqual(code, 2, result)
        self.assertEqual(result["young"][0]["wait_until"], "2026-11-26")

    def test_s1_provenance_lookup_failure_has_no_verdict(self):
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        fetch = npm_network(advisory=False, top_time=THREE_DAYS,
                            fail=f"/attestations/srv@{OLD_VERSION}")
        code, result = self.run_main(fetch, path, "--previous", previous, "--top", "srv")
        self.assertEqual(code, 2, result)
        self.assertTrue(any("could not establish npm provenance continuity" in line
                            for line in result["lines"]), result)

    def test_invalid_top_name_has_no_verdict_before_lookup(self):
        path = self.npm({"srv": FIX})
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        fetch = OfflineNetwork()
        code, result = self.run_main(fetch, path, "--previous", previous, "--top", "srv/extra")
        self.assertEqual(code, 2, result)
        self.assertTrue(any("invalid npm package name" in line for line in result["lines"]), result)
        self.assertEqual(fetch.calls, [])

    def test_uv_lock_fix_needs_single_pure_wheel(self):
        self.receipt("pypi", "demo")
        wheels = [(artifact["filename"], artifact["digests"]["sha256"]) for artifact in (
            package_file("demo", FIX, HASH),
            package_file("demo", FIX, OTHER_HASH, "-cp311-cp311-win_amd64.whl"),
        )]
        path = self.write("uv.lock", uv_lock("wrapper", "demo", FIX, wheels=wheels))
        previous = self.write("uv.lock", uv_lock("wrapper", "demo", OLD_VERSION), previous=True)
        fetch = pypi_network(
            old_files=[package_file("demo", OLD_VERSION, HASH, time=OLD),
                       package_file("demo", OLD_VERSION, SDIST_HASH, ".tar.gz", OLD)],
            fix_files=[package_file("demo", FIX, HASH),
                       package_file("demo", FIX, OTHER_HASH, "-cp311-cp311-win_amd64.whl"),
                       package_file("demo", FIX, SDIST_HASH, ".tar.gz")],
        )
        code, result = self.run_main(fetch, path, "--previous", previous, "--root-name", "wrapper")
        self.assertEqual(code, 2, result)
        self.assertEqual(result["needs_scan"], [])

    def test_requirements_sdist_only_entry_reports(self):
        path = self.requirements(FIX, (SDIST_HASH,))
        fetch = pypi_network(fix_files=[package_file("demo", FIX, SDIST_HASH, ".tar.gz", OLD)])
        code, result = self.run_main(fetch, path)
        self.assertEqual(code, 1, result)

    def test_pypi_previous_without_hashes_is_missing_provenance(self):
        self.receipt("pypi", "demo")
        path = self.requirements(FIX, (HASH,))
        previous = self.requirements(OLD_VERSION, (), previous=True, name="Demo")
        code, result = self.run_main(pypi_network(), path, "--previous", previous)
        self.assertEqual(code, 2, result)
        code, result = self.run_main(pypi_network(), path, "--previous", previous,
                                     "--override", f"demo={FIX}", "--override-reason", "reviewed")
        self.assertEqual(code, 0, result)

    def test_requirements_previous_hashes_bind_pypi_provenance(self):
        self.receipt("pypi", "demo")
        path = self.requirements(FIX, (HASH,))
        previous = self.requirements(OLD_VERSION, (SDIST_HASH,), previous=True)
        code, result = self.run_main(pypi_network(), path, "--previous", previous)
        self.assertEqual(code, 0, result)

    def test_requirements_age_exemption_cannot_cover_a_second_unscanned_artifact(self):
        self.receipt("pypi", "demo")
        candidate = "\n".join(f"{name}=={FIX} --hash=sha256:{digest}"
                              for name, digest in (("Demo", HASH), ("demo", OTHER_HASH)))
        path = self.write("requirements.txt", candidate)
        previous = self.requirements(OLD_VERSION, (SDIST_HASH,), previous=True)
        fetch = pypi_network(fix_files=[
            package_file("demo", FIX, HASH),
            package_file("demo", FIX, OTHER_HASH, "-cp311-cp311-win_amd64.whl"),
        ])
        fetch.pypi_files[("Demo", FIX)] = fetch.pypi_files[("demo", FIX)]
        code, result = self.run_main(fetch, path, "--previous", previous)
        self.assertEqual(code, 2, result)

    def test_user_override_needs_reason_and_exact_version(self):
        cases = (
            (self.npm({"srv": FIX}), ("--override", f"srv={FIX}")),
            (self.npm({"srv": FIX}), ("--override", "srv=^1.0.3", "--override-reason", "review")),
            (self.requirements(FIX, (HASH,)),
             ("--override", "demo=>=1.0", "--override-reason", "review")),
        )
        for path, options in cases:
            with self.subTest(options=options):
                fetch = OfflineNetwork()
                code, result = self.run_main(fetch, path, *options)
                self.assertEqual(code, 2, result)
                self.assertEqual(fetch.calls, [])

    def package_result(self, fetch, spec="npm:srv@1.0.0"):
        return self.run_main(fetch, "--package", spec, with_receipts=False)

    def test_package_mode_malware(self):
        fetch = OfflineNetwork(ghsa={("malware", "srv@1.0.0"): ["GHSA-malware"]})
        code, result = self.package_result(fetch)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["findings"][0]["kind"], "malware")

    def test_package_mode_security_kind(self):
        fetch = OfflineNetwork(ghsa={("reviewed", "srv@1.0.0"): ["GHSA-security"]})
        code, result = self.package_result(fetch)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["findings"][0]["kind"], "security")
        self.assertFalse(any(url.startswith(_lockcheck.NPM_REGISTRY_URL) for url in fetch.calls))

    def test_package_mode_offline_exits_2(self):
        code, result = self.package_result(OfflineNetwork(fail="api.osv.dev"))
        self.assertEqual(code, 2, result)

    def test_package_mode_security_hit_with_failed_source_exits_2(self):
        fetch = OfflineNetwork(ghsa={("reviewed", "srv@1.0.0"): ["GHSA-security"]},
                               fail="api.osv.dev")
        code, result = self.package_result(fetch)
        self.assertEqual(code, 2, result)

    def test_package_mode_rejects_bad_spec(self):
        for spec in ("npm:x", "foo:x@1", "npm:x@1&calc", " npm:x@1.0.0", "npm:x@^1.0.0",
                     "npm:x@1.0.0 ", "pypi:x@>=1", "pypi:x@1; python_version", "pypi:x@1 2"):
            with self.subTest(spec=spec):
                fetch = OfflineNetwork()
                code, result = self.package_result(fetch, spec)
                self.assertEqual(code, 2, result)
                self.assertEqual(fetch.calls, [])

    def test_package_mode_rejects_file_mode_options(self):
        previous = self.npm({"srv": OLD_VERSION}, previous=True)
        for options in (("--previous", previous), ("--no-fast-lane",)):
            with self.subTest(options=options):
                fetch = OfflineNetwork()
                code, result = self.run_main(fetch, "--package", "npm:srv@1.0.0", *options,
                                             with_receipts=False)
                self.assertEqual(code, 2, result)
                self.assertTrue(any("--package takes only a package spec" in line
                                    for line in result["lines"]), result)
                self.assertEqual(fetch.calls, [])

    def test_file_mode_rejects_invalid_age_policy(self):
        path = self.npm({"srv": OLD_VERSION})
        for options in (("--trusted-days", "8", "--min-age-days", "7"), ("--min-age-days", "-1")):
            with self.subTest(options=options):
                fetch = OfflineNetwork()
                code, result = self.run_main(fetch, path, *options)
                self.assertEqual(code, 2, result)
                self.assertTrue(any("0 <= trusted_days <= min_age_days" in line
                                    for line in result["lines"]), result)
                self.assertEqual(fetch.calls, [])

    def test_unreadable_file_mode_inputs_have_no_verdict(self):
        malformed = self.write("package-lock.json", "{")
        valid = self.npm({"srv": OLD_VERSION}, previous=True)
        bad_encoding = self.write("requirements.txt", "")
        Path(bad_encoding).write_bytes(bytes([255]))
        missing = str(self.root / "missing" / "package-lock.json")
        for options in ((missing,), (valid, "--previous", missing), (malformed,), (bad_encoding,)):
            for as_json in (False, True):
                with self.subTest(options=options, as_json=as_json):
                    fetch = OfflineNetwork()
                    code, result = self.run_main(fetch, *options, as_json=as_json)
                    output = "\n".join(result["lines"]) if as_json else result
                    self.assertEqual(code, 2, output)
                    self.assertIn("NO VERDICT", output)
                    self.assertEqual(fetch.calls, [])

    def test_json_is_one_object_and_parseable(self):
        code, result = self.run_main(OfflineNetwork(), "--invalid")
        self.assertEqual(code, 2, result)

    def test_unexpected_exception_has_no_verdict_with_and_without_json(self):
        for error in (RuntimeError("unexpected failure"), SystemExit(0),
                      _mcp_locked.Refused(1, "unexpected lookup refusal")):
            with self.subTest(error=error):
                fetch = mock.Mock(side_effect=error)
                code, result = self.package_result(fetch)
                self.assertEqual(code, 2, result)
                self.assertTrue(any("NO VERDICT" in line for line in result["lines"]), result)
                code, output = self.run_main(fetch, "--package", "npm:srv@1.0.0",
                                             with_receipts=False, as_json=False)
                self.assertEqual(code, 2, output)
                self.assertIn("NO VERDICT", output)

    def test_config_error_is_one_json_no_verdict(self):
        path = self.npm({"srv": OLD_VERSION})
        with mock.patch("_user_config.load_config", side_effect=RuntimeError("broken config")):
            code, result = self.run_main(OfflineNetwork(), path, with_receipts=False)
        self.assertEqual(code, 2, result)
        self.assertTrue(any("NO VERDICT" in line for line in result["lines"]), result)

    def test_import_does_not_load_skillspector(self):
        command = "import check_lock, sys; print(int('_skillspector' in sys.modules))"
        completed = subprocess.run([sys.executable, "-B", "-c", command], cwd=ROOT / "scripts",
                                   capture_output=True, text=True, check=True)
        self.assertEqual(completed.stdout.strip(), "0")


class HashedRequirementsTests(unittest.TestCase):
    def test_hashed_requirements_skips_comments_and_reads_continuation_lines(self):
        lines = [
            "# generated by the resolver",
            "demo==1.0 " + chr(92),
            f"    --hash=sha256:{HASH} " + chr(92),
            f"    --hash=sha256:{OTHER_HASH}",
            "    # via wrapper",
            f"other==2.0 --hash=sha256:{SDIST_HASH}  # via demo",
        ]
        result = _lockcheck.hashed_requirements("\n".join(lines))
        self.assertEqual([(entry.name, entry.version, entry.hashes) for entry in result],
                         [("demo", "1.0", (HASH, OTHER_HASH)), ("other", "2.0", (SDIST_HASH,))])

    def test_hashed_requirements_refuses_missing_hash_by_default(self):
        with self.assertRaises(_lockcheck.NoVerdict):
            _lockcheck.hashed_requirements("demo==1.0")

    def test_hashed_requirements_accepts_previous_pin_without_hash(self):
        result = _lockcheck.hashed_requirements("demo==1.0", require_hashes=False)
        self.assertEqual(result[0].hashes, ())

    def test_hashed_requirements_refuses_ranges_and_unreadable_lines_in_both_modes(self):
        for pin in ("demo>=1.0", "demo", "demo==latest", f"demo==1.0 --hash=sha256:abc",
                    f"demo==1.0 --hash=sha256:{HASH} " + chr(92)):
            for require_hashes in (True, False):
                with self.subTest(pin=pin, require_hashes=require_hashes):
                    with self.assertRaises(_lockcheck.NoVerdict):
                        _lockcheck.hashed_requirements(pin, require_hashes=require_hashes)
