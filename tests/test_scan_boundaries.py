"""Regression cases for the failures found in the 0.3.0 self review."""
import copy
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from test_reviewed_baseline import clean_report, ss
import _url_resolver as resolver
import install_skill as installer
import scan_cli
import scan_mcp
import scan_url


class ScanBoundaryTests(unittest.TestCase):
    def test_only_installation_env_is_implicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'trusted'
            with patch.object(ss, '__file__', str(root / 'scripts' / '_skillspector.py')), \
                 patch.dict(ss.os.environ, {}, clear=True), \
                 patch.object(ss, 'load_env_file') as load:
                ss.load_agent_guard_env()
                load.assert_called_once_with((root / '.env').resolve())

    def test_installer_does_not_log_environment_secrets(self):
        entry = {'command': 'server', 'args': [], 'env': {'API_KEY': 'test-secret-value'}}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(installer, 'HOME', Path(tmp)), \
             patch.object(installer.subprocess, 'run') as run:
            for dry in (True, False):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    installer.add_to_claude_code('demo', entry, dry)
                self.assertNotIn('test-secret-value', output.getvalue())
            run.assert_not_called()
            stored = json.loads((Path(tmp) / '.claude.json').read_text())
            self.assertEqual(stored['mcpServers']['demo'], entry)

    def test_config_update_uses_private_temporary_files_and_preserves_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text('{"original": true}')
            path.chmod(0o600)
            old_mode = path.stat().st_mode
            sentinel = Path(tmp) / 'config.json.tmp'
            sentinel.write_text('do not overwrite')
            installer.write_json(path, {'updated': True}, False)
            self.assertEqual(json.loads(path.read_text()), {'updated': True})
            self.assertEqual(json.loads(path.with_suffix('.json.bak').read_text()), {'original': True})
            self.assertEqual(sentinel.read_text(), 'do not overwrite')
            self.assertEqual(path.stat().st_mode, old_mode)
            self.assertEqual(list(Path(tmp).glob('.guard-*')), [])

    @unittest.skipUnless(installer.os.name == 'nt', 'Windows junction fallback')
    def test_windows_junction_handles_shell_metacharacters_as_literal_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'target & literal'
            target.mkdir()
            link = Path(tmp) / 'link & literal'
            with patch.object(Path, 'symlink_to', side_effect=OSError('no symlink privilege')):
                installer.make_link(target, link, dry=False)
            self.assertEqual(link.resolve(), target.resolve())

    def test_workspace_selection_does_not_write_during_dry_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'not-created'
            with patch.dict(installer.os.environ, {'AGENT_GUARD_WORKSPACE': str(target)}):
                self.assertEqual(installer.workspace_default(), target)
                self.assertFalse(target.exists())

    def test_malcontent_error_cannot_be_safe(self):
        with patch.object(scan_cli.shutil, 'which', return_value='docker'), \
             patch.object(scan_cli, 'run_bounded', return_value=subprocess.CompletedProcess(
                 [], 3, '{"Files": {"file": {"RiskLevel": "LOW"}}}', '')):
            self.assertEqual(scan_cli.run_malcontent(Path('file')), 2)

    def test_sandbox_keeps_scanner_credentials_out_of_target_and_cleans_up(self):
        with patch.object(scan_mcp, 'need_mcp_scanner'), \
             patch.object(scan_mcp, 'build_sandbox_image'), \
             patch.object(scan_mcp.shutil, 'which', return_value='docker'), \
             patch.object(scan_mcp, 'MCP_SCANNER', 'mcp-scanner'), \
             patch.object(scan_mcp, 'CISCO_LLM_KEY', 'runtime-test-secret'), \
             patch.object(scan_mcp, 'CISCO_LLM_MODEL', 'test-model'), \
             patch.object(scan_mcp, 'run_cisco', return_value=0) as scan, \
             patch.object(scan_mcp._egress.Capture, 'start') as capture, \
             patch.object(scan_mcp._egress, 'verdict', return_value=0), \
             patch.object(scan_mcp.subprocess, 'run') as cleanup:
            capture.return_value.name = 'agent-guard-net-test'
            self.assertEqual(scan_mcp.run_sandbox(['python', '-c', 'print(1)']), 0)
            argv = scan.call_args.args[0]
            self.assertEqual(argv[0], 'mcp-scanner')
            self.assertIn('--stdio-command', argv)
            self.assertIn('docker', argv)
            self.assertNotIn('runtime-test-secret', ' '.join(argv))
            self.assertNotIn('API_KEY', ' '.join(argv))
            self.assertNotIn('--stdio-arg=-v', argv)
            self.assertEqual(scan.call_args.kwargs['env']['MCP_SCANNER_LLM_API_KEY'], 'runtime-test-secret')
            self.assertIn('--stdio-arg=--cap-drop=ALL', argv)
            cleanup_args = cleanup.call_args.args[0]
            self.assertEqual(cleanup_args[:3], ['docker', 'rm', '--force'])
            self.assertTrue(cleanup_args[3].startswith('agent-guard-scan-'))
            scan.side_effect = RuntimeError('failed handshake')
            with self.assertRaises(RuntimeError):
                scan_mcp.run_sandbox(['python', '-c', 'print(1)'])
            self.assertEqual(cleanup.call_count, 2)

    def test_uvx_from_scans_provider_package(self):
        for command in ['uvx --from actual-package entrypoint', 'uvx --from=actual-package entrypoint']:
            self.assertEqual(scan_url.package_page_from_command(command),
                             ('pypi', 'https://pypi.org/project/actual-package/'))

    def test_archive_rejects_sibling_with_same_path_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'source'
            dest.mkdir()
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w') as archive:
                archive.writestr('../source-other/payload.py', 'untrusted')
            for module, error in [(resolver, ValueError), (scan_mcp, SystemExit)]:
                with self.assertRaises(error):
                    module.safe_extract_zip(buf.getvalue(), dest)
            self.assertFalse((Path(tmp) / 'source-other').exists())

    def test_acquisition_returns_the_downloaded_version(self):
        cases = [('pypi', 'demo', {'info': {'version': '1.2.3'}, 'releases': {'1.2.3': [
                    {'packagetype': 'sdist', 'url': 'https://example.com/source'}]}}, 'demo==1.2.3'),
                 ('npm', '@example/demo@latest', {'dist-tags': {'latest': '1.2.3'},
                    'versions': {'1.2.3': {'dist': {'tarball': 'https://example.com/source'}}}},
                  '@example/demo@1.2.3')]
        for ecosystem, spec, metadata, expected in cases:
            with patch.object(scan_mcp, 'http_json', return_value=metadata), \
                 patch.object(scan_mcp, 'http_bytes', return_value=b'archive'), \
                 patch.object(scan_mcp, 'safe_extract_tar') as extract:
                self.assertEqual(getattr(scan_mcp, 'fetch_' + ecosystem)(spec, Path('.')), expected)
                extract.assert_called_once_with(b'archive', Path('.'))

    def judge(self, data, exit_code=0, reviewed=False):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            report = Path(tmp) / 'report.json'
            report.write_text(json.dumps(data), encoding='utf-8')
            return ss.verdict_skillspector(report, exit_code, reviewed_baseline=reviewed)

    def test_scanner_error_cannot_be_safe(self):
        self.assertEqual(self.judge(clean_report(), 3), 2)
        blocked = clean_report()
        blocked['issues'] = [{'id': 'PE3', 'severity': 'HIGH'}]
        self.assertEqual(self.judge(blocked, 1), 1)

    def test_missing_success_and_incomplete_coverage_cannot_be_safe(self):
        data = clean_report()
        del data['execution_successful']
        del data['analysis_completeness']['execution_successful']
        self.assertEqual(self.judge(data), 2)
        for field, value in [('is_complete', False), ('entirely_uninspected_files', 1),
                             ('partially_inspected_files', 1), ('entirely_uninspected_files', None)]:
            data = clean_report()
            data['analysis_completeness'][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(self.judge(data), 2)

    def test_invalid_scores_and_structures_fail_closed(self):
        for value in [None, '0', True, -1, 101, float('nan'), float('inf')]:
            data = clean_report()
            data['risk_assessment']['score'] = value
            self.assertEqual(self.judge(data), 2)
        for field, value in [('metadata', []), ('risk_assessment', []), ('issues', {}),
                             ('analysis_completeness', None), ('suppressed_count', -1),
                             ('suppressed', {}), ('issues', [{'location': 'bad'}])]:
            with self.subTest(field=field):
                self.assertEqual(self.judge({**clean_report(), field: value}), 2)

    def test_llm_requires_positive_metadata_and_valid_accounting(self):
        valid = {'llm_requested': True, 'llm_available': True,
                 'llm_calls_attempted': 5, 'llm_calls_succeeded': 5}
        self.assertEqual(ss.llm_run_incomplete({'metadata': valid}, expected=True), '')
        for meta in [None, [], {}, {**valid, 'llm_requested': False},
                     {**valid, 'llm_available': 'true'}, {**valid, 'llm_calls_attempted': True},
                     {**valid, 'llm_calls_succeeded': 4}, {**valid, 'llm_calls_succeeded': 6}]:
            self.assertTrue(ss.llm_run_incomplete({'metadata': meta}, expected=True))

    def test_reference_review_does_not_accept_other_files_or_analyzer_failures(self):
        data = clean_report()
        data.update(suppressed_count=1, suppressed=[{'id': 'AE1', 'suppressed': True,
            'location': {'file': 'SKILL.md'}, 'suppression_reason': 'Reviewed documentation placeholders'}])
        exception = {'phase': 'reference_resolution', 'reason_code': 'reference_missing',
                     'path': 'SKILL.md', 'fatal': False}
        data['analysis_completeness'].update(is_complete=False, coverage_percent=100,
                                             ledger_exceptions=[exception])
        self.assertEqual(self.judge(data, reviewed=True), 0)
        # An ambiguous reference (several bundled matches) needs the review:
        # accepted with the reviewed AE1 fingerprints, refused without them.
        ambiguous = copy.deepcopy(data)
        ambiguous['analysis_completeness']['ledger_exceptions'][0]['reason_code'] = \
            'reference_unresolved'
        self.assertEqual(self.judge(ambiguous, reviewed=True), 0)
        self.assertEqual(self.judge(ambiguous), 2)
        # A fatal exception, or one from another phase, is not reference noise and
        # blocks on its own -- the reviewed baseline cannot rescue it.
        for change in [{'fatal': True}, {'phase': 'analyzer'}]:
            bad = copy.deepcopy(data)
            bad['analysis_completeness']['ledger_exceptions'][0].update(change)
            self.assertEqual(self.judge(bad, reviewed=True), 2)
        bad = copy.deepcopy(data)
        bad['analysis_completeness']['partially_inspected_files'] = 1
        self.assertEqual(self.judge(bad, reviewed=True), 2)

        # Whether the baseline's AE1 fingerprints actually cover the file that
        # carries the unresolved reference only decides anything once completeness
        # is demanded; by default an unresolved reference never blocks, so the
        # path it sits in cannot change the verdict either.
        original = ss.FAIL_ON_INCOMPLETE
        try:
            ss.FAIL_ON_INCOMPLETE = True
            self.assertEqual(self.judge(data, reviewed=True), 0)
            for change in [{'path': 'other.md'}, {'fatal': True}, {'phase': 'analyzer'}]:
                bad = copy.deepcopy(data)
                bad['analysis_completeness']['ledger_exceptions'][0].update(change)
                self.assertEqual(self.judge(bad, reviewed=True), 2)
            # Without a reviewed baseline the strict mode refuses the verdict.
            self.assertEqual(self.judge(data), 2)
        finally:
            ss.FAIL_ON_INCOMPLETE = original

    def test_guarddog_capabilities_cannot_hide_rule_errors(self):
        self.assertEqual(scan_cli.guarddog_verdict({'issues': 1,
            'results': {'capability-network': ['HTTP client']}, 'errors': {'malware': 'failed'}}), 2)

    def test_guarddog_exit_error_cannot_be_safe(self):
        with patch.object(scan_cli, 'guarddog_command', return_value=['guarddog']), \
             patch.object(scan_cli, 'run_bounded', return_value=subprocess.CompletedProcess(
                 [], 3, '{"issues": 0, "results": {}}', '')):
            self.assertEqual(scan_cli.run_guarddog('pypi', 'demo'), 2)

    def test_cisco_requires_success_and_analyzed_tools(self):
        for output, code in [('Total tools scanned: 2\nUnsafe items: 0', 1),
                             ('Unsafe items: 0', 0), ('Total tools scanned: 0\nUnsafe items: 0', 0)]:
            self.assertEqual(scan_mcp.verdict(output, code), 2)
        self.assertEqual(scan_mcp.verdict('Total tools scanned: 2\nUnsafe items: 0', 0), 0)

    def test_unresolved_git_ref_never_falls_back_to_mutable_branch(self):
        for result in [{}, {'sha': 'main'}]:
            with patch.object(resolver, 'http_json', return_value=result):
                with self.assertRaises(resolver.FetchError):
                    resolver.github_ref_sha('example', 'demo', 'main')
        with patch.object(resolver, 'http_json', side_effect=resolver.FetchError('offline')):
            with self.assertRaises(resolver.FetchError):
                resolver.github_ref_sha('example', 'demo', 'v1')
            self.assertEqual(resolver.github_ref_sha('example', 'demo', 'a' * 40), 'a' * 40)

    def test_git_installer_rejects_mutable_refs_and_escaping_subdirectory(self):
        base = 'https://github.com/example/demo@'
        for suffix in ['main', 'v1.0', 'abc123', 'a' * 40 + '#subdirectory=../outside']:
            with self.assertRaises(SystemExit):
                installer.normalize_git_source(base + suffix)
        self.assertEqual(installer.normalize_git_source(base + 'a' * 40), 'git+' + base + 'a' * 40)

    @patch.object(installer, "detect_tools", return_value={})
    def test_skill_installer_rejects_path_names_existing_content_and_wrong_links(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            source.mkdir()
            (source / 'SKILL.md').write_text('# Demo')
            workspace = root / 'workspace'
            workspace.mkdir()
            existing = workspace / 'demo'
            existing.mkdir()
            (existing / 'SKILL.md').write_text('# Unreviewed')
            for name in ['../escape', 'bad/name', 'demo']:
                with self.assertRaises(SystemExit):
                    installer.install_skill(source, name, workspace, dry=False, selected=[])
            with self.assertRaises(SystemExit):
                installer.make_link(source, existing, dry=False)
            self.assertEqual((existing / 'SKILL.md').read_text(), '# Unreviewed')

    @patch.object(installer, "detect_tools", return_value={})
    def test_skill_installer_rescans_exact_tree_before_copying(self, _detect):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source'
            source.mkdir()
            (source / 'SKILL.md').write_text('# Demo')
            workspace = root / 'workspace'
            workspace.mkdir()
            with patch.object(installer, 'run_skillspector', return_value=1) as scan:
                with self.assertRaises(SystemExit):
                    installer.install_skill(source, 'demo', workspace, dry=False, selected=[])
                scan.assert_called_once()
                self.assertNotEqual(scan.call_args.args[0], source)
            self.assertFalse((workspace / 'demo').exists())
            with patch.object(installer, 'run_skillspector', return_value=0), \
                 patch.object(installer, 'detect_tools', return_value={}):
                installer.install_skill(source, 'demo', workspace, dry=False, selected=[])
            self.assertEqual((workspace / 'demo' / 'SKILL.md').read_text(), '# Demo')

    @patch.object(installer, "detect_tools", return_value={})
    def test_installer_publishes_scanned_copy_and_rejects_stage_mutation(self, _detect):
        for mutate_stage in (False, True):
            with self.subTest(mutate_stage=mutate_stage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / "source"
                source.mkdir()
                (source / "SKILL.md").write_text("reviewed")
                workspace = root / "workspace"
                policy = root / "review.json"
                def scan(candidate, **kwargs):
                    self.assertEqual(kwargs["baseline"], policy)
                    self.assertEqual((candidate / "SKILL.md").read_text(), "reviewed")
                    (source / "SKILL.md").write_text("changed source")
                    if mutate_stage:
                        (candidate / "SKILL.md").write_text("changed stage")
                    return 0
                with patch.object(installer, "run_skillspector", side_effect=scan):
                    if mutate_stage:
                        with self.assertRaises(SystemExit):
                            installer.install_skill(source, "demo", workspace, False, baseline=policy)
                        self.assertFalse((workspace / "demo").exists())
                    else:
                        installer.install_skill(source, "demo", workspace, False, baseline=policy)
                        self.assertEqual((workspace / "demo" / "SKILL.md").read_text(), "reviewed")
                self.assertEqual(list(workspace.glob(".guard-stage-*")), [])

    def test_missing_pypi_release_does_not_scan_latest(self):
        with patch.object(scan_mcp, 'http_json', return_value={'info': {'version': '2'},
                'releases': {'2': [{'packagetype': 'sdist', 'url': 'https://example.com/latest'}]},
                'urls': [{'packagetype': 'sdist', 'url': 'https://example.com/latest'}]}), \
             patch.object(scan_mcp, 'http_bytes') as download:
            with self.assertRaises(SystemExit):
                scan_mcp.fetch_pypi('demo==1', Path('.'))
            download.assert_not_called()

    def test_registry_scan_offers_only_resolved_version(self):
        for ecosystem, spec, pinned in [('pypi', 'demo', 'demo==1.2.3'),
                                        ('npm', '@example/demo', '@example/demo@1.2.3')]:
            source = resolver.ResolvedSource(kind=ecosystem, install_hint=spec)
            with patch.object(scan_url, 'fetch_' + ecosystem, return_value=pinned), \
                 patch.object(scan_url, 'run_mcp_static', return_value=0), \
                 patch.object(scan_url._dynamic, 'run', return_value=0) as dynamic, \
                 patch.object(scan_url, 'offer_mcp_install') as offer:
                self.assertEqual(scan_url.scan_resolved(source, 'mcp-source', True), 0)
                self.assertIn(pinned, offer.call_args.args[2])
                dynamic.assert_called_once_with(ecosystem, pinned)

    def test_catalog_cannot_reoffer_original_unpinned_command_after_source_scan(self):
        with patch.object(scan_url, 'scan_candidate_source_url', return_value=0), \
             patch.object(scan_url, 'offer_mcp_install') as offer:
            self.assertEqual(scan_url.scan_install_command('uvx demo', False, False), 0)
            offer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
