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

    def test_plain_docs_stay_documentation(self):
        for rel in ("README.md", "docs/guide.md", "logo.svg", ".github/ISSUE.md",
                    ".github/workflows/ci.yml", "LICENSE", "commands/shot.png",
                    ".gitmodules", ".editorconfig", "CHANGELOG", "Changes",
                    "HISTORY", "AUTHORS", "CONTRIBUTORS"):
            self.assertTrue(self.doc(rel), rel)

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
