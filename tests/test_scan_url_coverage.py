"""Coverage gaps of scan_url / _url_resolver found in the 0.5.1 PR review."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import _url_resolver as resolver
import scan_url


def write(root: Path, rel: str, text: str = "x") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class NoScanCandidatesTests(unittest.TestCase):
    def run_catalog(self, rc, **kwargs):
        with tempfile.TemporaryDirectory() as d:
            page = Path(d) / "catalog-page.md"
            page.write_text("# Market\n", encoding="utf-8")
            source = scan_url.ResolvedSource(
                kind="catalog", source_path=page,
                remote_urls=["https://api.example.com/mcp"],
                install_commands=["uvx example-mcp"], **kwargs)
            out = io.StringIO()
            with patch.object(scan_url, "scan_catalog", lambda p: rc), \
                 contextlib.redirect_stdout(out):
                result = scan_url.scan_resolved(source, "catalog", dry_run=True,
                                                scan_candidates=False)
        return result, out.getvalue()

    def test_unscanned_candidates_are_no_verdict(self):
        result, out = self.run_catalog(0)
        self.assertEqual(result, 2)
        self.assertIn("https://api.example.com/mcp", out)
        self.assertIn("uvx example-mcp", out)
        self.assertIn("NO VERDICT", out)

    def test_block_of_readme_still_wins(self):
        result, _ = self.run_catalog(1)
        self.assertEqual(result, 1)


class ExitTwoLabelTests(unittest.TestCase):
    def test_exit_2_lines_say_no_verdict_not_block(self):
        out = io.StringIO()
        with patch.object(scan_url, "resolve_url", side_effect=scan_url.FetchError("gone")), \
             contextlib.redirect_stdout(out):
            self.assertEqual(scan_url.scan_candidate_source_url("https://example.com/x"), 2)
        self.assertIn("[NO VERDICT] candidate fetch failed", out.getvalue())
        self.assertNotIn("[BLOCK]", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(scan_url.scan_install_command("uvx 'unclosed", True, True), 2)
        self.assertIn("[NO VERDICT] Could not parse install command", out.getvalue())
        self.assertNotIn("[BLOCK]", out.getvalue())

    def test_listing_without_installable_source_says_no_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            page = Path(d) / "catalog-page.md"
            page.write_text("# Market\n", encoding="utf-8")
            source = scan_url.ResolvedSource(kind="catalog", source_path=page)
            out = io.StringIO()
            with patch.object(scan_url, "scan_catalog", lambda p: 0), \
                 contextlib.redirect_stdout(out):
                self.assertEqual(scan_url.scan_resolved(
                    source, "catalog", dry_run=True, scan_candidates=False), 2)
        self.assertIn("[NO VERDICT] NO INSTALLABLE SOURCE", out.getvalue())
        self.assertNotIn("[BLOCK]", out.getvalue())


class DocumentationFileTests(unittest.TestCase):
    def doc(self, rel, root=None):
        return scan_url.is_documentation_file(Path(rel), root)

    def test_prompt_files_are_not_documentation(self):
        for rel in ("CLAUDE.md", "sub/Agents.MD", "GEMINI.md", ".cursorrules",
                    ".windsurfrules", "commands/x.md", "a/agents/x.txt",
                    "prompts/p.md", "rules/r.rst", "hooks/h.markdown",
                    "output-styles/o.md", ".claude/notes.md", ".cursor/x.md",
                    ".codex/x.md", ".gemini/x.md", ".windsurf/x.md",
                    ".github/prompts/x.md", ".github/instructions/x.md",
                    ".github/agents/x.md", ".github/copilot-instructions.md",
                    "Commands/Deploy.md"):
            self.assertFalse(self.doc(rel), rel)

    def test_wider_block_list_of_prompt_files_and_folders(self):
        for rel in ("Agent.md", "AGENT.MD", "sub/copilot-instructions.md", ".clinerules",
                    "x/.clinerules", "a.prompt.md", "docs/b.chatmode.md",
                    "c.instructions.md", "prompt/p.md", "command/c.md", "agent/a.md",
                    "rule/r.md", "chatmodes/m.md", "instructions/i.md",
                    "workflows/w.md", "docs/Rules/r.txt", "Prompts/P.md",
                    ".github/chatmodes/m.chatmode.md", ".github/copilot/x.md",
                    ".github/workflows/ci.yml", ".github/workflows/README.md",
                    ".roo/rules/r.md", ".kiro/steering/s.md", ".clinerules/r.md",
                    ".vitepress/notes.md", "pkg/.hidden/readme.md"):
            self.assertFalse(self.doc(rel), rel)

    def test_plain_docs_stay_documentation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in ("LICENSE", "CHANGELOG", "Changes", "HISTORY", "AUTHORS",
                        "CONTRIBUTORS", "LICENSE-MIT"):
                write(root, rel, "1.0 notes\n")
                self.assertTrue(self.doc(rel, root), rel)
        for rel in ("README.md", "docs/guide.md", "logo.svg", ".github/ISSUE.md",
                    "commands/shot.png", ".gitmodules", ".editorconfig",
                    ".github/ISSUE_TEMPLATE/bug.yml", ".github/ISSUE_TEMPLATE/config.yml",
                    ".github/PULL_REQUEST_TEMPLATE.md", ".github/FUNDING.yml",
                    ".github/SECURITY.md", ".github/assets/screenshot.png",
                    ".git/info.txt"):
            self.assertTrue(self.doc(rel), rel)

    def test_extensionless_prose_names_must_not_start_with_a_shebang(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in ("CHANGELOG", "HISTORY", "LICENSE", "licenseinstall", "Authors"):
                write(root, rel, "#!/bin/sh\necho hi\n")
                self.assertFalse(self.doc(rel, root), rel)
            write(root, "CHANGELOG", "# 1.0\n")
            self.assertTrue(self.doc("CHANGELOG", root))
            # without the tree, or when the file is missing, nothing can be said
            self.assertFalse(self.doc("CHANGELOG"))
            self.assertFalse(self.doc("HISTORY", root))

    def test_code_without_doc_name_is_not_documentation(self):
        self.assertFalse(self.doc("CHANGELOG.sh"))
        self.assertFalse(self.doc("install.sh"))

    def test_marketplace_metadata_is_documentation_only_when_pure(self):
        pure = {"name": "m", "owner": {"name": "o"}, "metadata": {"version": "1"},
                "plugins": [{"name": "p", "source": "./p", "description": "d",
                             "keywords": ["a"], "strict": False}]}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, ".claude-plugin/marketplace.json", json.dumps(pure))
            write(root, ".claude-plugin/sub/plugin.json", json.dumps({"name": "p"}))
            self.assertTrue(self.doc(".claude-plugin/marketplace.json", root))
            self.assertTrue(self.doc(".claude-plugin/sub/plugin.json", root))
            # without the root the content cannot be checked: not documentation
            self.assertFalse(self.doc(".claude-plugin/marketplace.json"))

    def test_manifest_sources_must_be_relative_paths_inside_the_repo(self):
        def manifest(**plugin):
            return {"name": "m", "plugins": [dict({"name": "p"}, **plugin)]}

        good = [manifest(source="./p"), manifest(source="./plugins/p"),
                manifest(source="./p", skills="./p/skills"),
                manifest(source="./p", skills=["./a", "./b"]),
                {"name": "m", "metadata": {"pluginRoot": "./plugins"},
                 "plugins": [{"name": "p", "source": "./p"}]}]
        bad = [manifest(source={"source": "github", "repo": "a/b"}),
               manifest(source={"source": "url", "url": "https://x.example/p.git"}),
               manifest(source="https://github.com/a/b"),
               manifest(source="github:a/b"),
               manifest(source="git@github.com:a/b.git"),
               manifest(source="/abs/p"),
               manifest(source="C:\\p"),
               manifest(source="p"),
               manifest(source="../p"),
               manifest(source="./a/../../p"),
               manifest(source="./a\\..\\p"),
               manifest(source=5),
               manifest(source="./p", skills="../s"),
               manifest(source="./p", skills=["./ok", "/abs"]),
               manifest(source="./p", skills=["https://x.example/s"]),
               manifest(source="./p", skills=[1]),
               {"name": "m", "metadata": {"pluginRoot": "../x"},
                "plugins": [{"name": "p", "source": "./p"}]}]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for content in good:
                write(root, ".claude-plugin/marketplace.json", json.dumps(content))
                self.assertTrue(self.doc(".claude-plugin/marketplace.json", root),
                                str(content))
            for content in bad:
                write(root, ".claude-plugin/marketplace.json", json.dumps(content))
                self.assertFalse(self.doc(".claude-plugin/marketplace.json", root),
                                 str(content))

    def test_deeply_nested_or_failing_manifest_is_not_documentation_and_never_crashes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            write(root, ".claude-plugin/marketplace.json", "[" * 200000 + "]" * 200000)
            self.assertFalse(self.doc(".claude-plugin/marketplace.json", root))
            write(root, ".claude-plugin/plugin.json", '{"name": "p"}')
            self.assertTrue(self.doc(".claude-plugin/plugin.json", root))
            with patch.object(scan_url.json, "loads", side_effect=KeyError("boom")):
                self.assertFalse(self.doc(".claude-plugin/plugin.json", root))
            skills = [root / "skills" / "one"]
            write(root, "skills/one/SKILL.md", "---\nname: one\n---\n")
            write(root, ".claude-plugin/marketplace.json", "[" * 200000 + "]" * 200000)
            self.assertEqual(scan_url.files_outside_skills(root, skills),
                             [Path(".claude-plugin/marketplace.json")])

    def test_marketplace_with_executable_keys_is_not_documentation(self):
        bad_docs = [
            {"name": "m", "hooks": {}},
            {"name": "m", "mcpServers": {}},
            {"name": "m", "plugins": [{"name": "p", "lspServers": {}}]},
            {"name": "m", "plugins": [{"name": "p", "commands": "./c"}]},
            {"name": "m", "plugins": [{"name": "p", "agents": []}]},
            {"name": "m", "outputStyles": []},
            {"name": "m", "plugins": {"name": "p"}},
            {"name": "m", "plugins": ["p"]},
            {"name": "m", "description": 5},
            ["name"],
        ]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for i, content in enumerate(bad_docs):
                write(root, ".claude-plugin/marketplace.json", json.dumps(content))
                self.assertFalse(self.doc(".claude-plugin/marketplace.json", root),
                                 str(content))
            write(root, ".claude-plugin/marketplace.json", "{not json")
            self.assertFalse(self.doc(".claude-plugin/marketplace.json", root))
            write(root, ".claude-plugin/marketplace.json",
                  '{"name": "a", "hooks": {}, "hooks": 1}')
            self.assertFalse(self.doc(".claude-plugin/marketplace.json", root))
            (root / ".claude-plugin" / "marketplace.json").unlink()
            # missing file: read error => not documentation
            self.assertFalse(self.doc(".claude-plugin/marketplace.json", root))

    def collection(self, root, marketplace):
        write(root, "skills/one/SKILL.md", "---\nname: one\n---\n")
        write(root, ".claude-plugin/marketplace.json", json.dumps(marketplace))
        write(root, ".gitmodules", "")
        write(root, ".editorconfig", "root = true\n")
        write(root, "CHANGELOG", "1.0\n")
        return [root / "skills" / "one"]

    def test_collection_with_metadata_only_has_no_unscanned_rest(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            skills = self.collection(root, {"name": "m", "plugins": []})
            self.assertEqual(scan_url.files_outside_skills(root, skills), [])

    def test_collection_with_hooks_or_mcp_servers_is_unscanned(self):
        for key in ("hooks", "mcpServers"):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                skills = self.collection(root, {"name": "m", key: {}})
                self.assertEqual(scan_url.files_outside_skills(root, skills),
                                 [Path(".claude-plugin/marketplace.json")])


class FirstChildDirTests(unittest.TestCase):
    def test_sibling_file_prevents_descending(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pkg").mkdir()
            write(root, "install.sh")
            self.assertEqual(resolver.first_child_dir(root), root)

    def test_single_directory_is_entered(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "pkg").mkdir()
            self.assertEqual(resolver.first_child_dir(root), root / "pkg")


class PackageVersionTests(unittest.TestCase):
    def resolve(self, url):
        return resolver.resolve_url(url, Path("."))

    def test_pypi_version_is_kept(self):
        self.assertEqual(self.resolve("https://pypi.org/project/x/1.2.3/").install_hint,
                         "x==1.2.3")
        self.assertEqual(self.resolve("https://pypi.org/project/x/").install_hint, "x")

    def test_npm_version_is_kept(self):
        self.assertEqual(
            self.resolve("https://www.npmjs.com/package/x/v/1.2.3").install_hint,
            "x@1.2.3")
        self.assertEqual(
            self.resolve("https://www.npmjs.com/package/@s/x/v/1.2.3").install_hint,
            "@s/x@1.2.3")
        self.assertEqual(
            self.resolve("https://www.npmjs.com/package/@s/x").install_hint, "@s/x")

    def test_unknown_extra_segments_are_refused_not_ignored(self):
        for url in ("https://pypi.org/project/x/1.2.3/extra/",
                    "https://www.npmjs.com/package/x/foo/1.2.3"):
            with self.assertRaises(resolver.FetchError):
                self.resolve(url)


    def test_npm_missing_version_is_refused_not_replaced(self):
        import scan_mcp
        meta = {"dist-tags": {"latest": "2.0.0"}, "versions": {"2.0.0": {}}}
        with patch.object(scan_mcp, "http_json", lambda url: meta):
            with self.assertRaises(SystemExit) as cm:
                scan_mcp.fetch_npm("x@1.2.3", Path("."))
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
