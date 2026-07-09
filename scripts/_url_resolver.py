#!/usr/bin/env python3
"""URL/source resolution helpers for agent-guard.

Resolvers fetch immutable source artifacts where possible. Unknown web pages are
treated as catalogs: scan the page text, extract candidate links, but do not
install anything from the page itself.
"""

from __future__ import annotations

import io
import json
import html
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path


GITHUB_HOSTS = {"github.com", "www.github.com"}
NON_SOURCE_GITHUB_REPOS = {
    ("openai", "codex"),
}
GITHUB_LINK_RE = re.compile(r"https://github\.com/[^\s<)\]>\"']+")
URL_RE = re.compile(r"https?://[^\s<)\]>\"']+")
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; agent-guard/1.0; "
        "+https://github.com/elliottwaves-20/agent-guard)"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
LAST_RENDER_FETCH_ERROR = ""


class FetchError(RuntimeError):
    """A URL could not be fetched safely enough to scan."""


def command_args(command: str, url: str) -> list[str]:
    args = shlex.split(command, posix=os.name != "nt")
    if any("{url}" in arg for arg in args):
        args = [arg.replace("{url}", url) for arg in args]
    else:
        args = args + [url]
    resolved = shutil.which(args[0])
    if resolved:
        args[0] = resolved
    return args


@dataclass
class ResolvedSource:
    kind: str
    source_path: Path | None = None
    label: str = ""
    pinned_ref: str = ""
    install_hint: str = ""
    urls: list[str] | None = None
    source_urls: list[str] | None = None
    remote_urls: list[str] | None = None
    install_commands: list[str] | None = None


class CompactHTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self.skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        text = " ".join(data.split())
        if text:
            self.parts.append(text)

    def text(self) -> str:
        return "\n".join(self.parts)


def http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={**DEFAULT_HEADERS, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise FetchError(format_fetch_error(url, e.code, body)) from e
    except urllib.error.URLError as e:
        raise FetchError(f"could not fetch {url}: {e.reason}") from e


def http_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers=DEFAULT_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise FetchError(format_fetch_error(url, e.code, body)) from e
    except urllib.error.URLError as e:
        raise FetchError(f"could not fetch {url}: {e.reason}") from e
    text = data[:200000].decode("utf-8", errors="replace")
    if is_security_checkpoint(text):
        raise FetchError(
            f"could not fetch {url}: site returned a browser security checkpoint "
            "(JavaScript challenge). agent-guard cannot scan a marketplace page "
            "unless the page content or a concrete source/archive URL is reachable."
        )
    return data


def fetch_rendered_page(url: str) -> str | None:
    """Render a marketplace page when static HTTP sees a JS checkpoint.

    This executes the marketplace page in a fresh browser context, then returns
    only rendered HTML/text for catalog scanning. It is not used for source
    execution or installation. Users can also provide AGENT_GUARD_FETCH_COMMAND,
    a command that prints rendered HTML/Markdown to stdout; use {url} as an
    optional placeholder.
    """
    global LAST_RENDER_FETCH_ERROR
    LAST_RENDER_FETCH_ERROR = ""
    errors: list[str] = []
    if os.environ.get("AGENT_GUARD_DISABLE_RENDER_FETCH"):
        LAST_RENDER_FETCH_ERROR = "render fetch disabled by AGENT_GUARD_DISABLE_RENDER_FETCH"
        return None
    external = os.environ.get("AGENT_GUARD_FETCH_COMMAND", "").strip()
    if external:
        try:
            r = subprocess.run(command_args(external, url), capture_output=True,
                               text=True, timeout=90)
        except subprocess.TimeoutExpired:
            errors.append("AGENT_GUARD_FETCH_COMMAND timed out")
            LAST_RENDER_FETCH_ERROR = "; ".join(errors)
            return None
        except OSError as e:
            errors.append(f"AGENT_GUARD_FETCH_COMMAND failed to start: {e}")
            LAST_RENDER_FETCH_ERROR = "; ".join(errors)
            return None
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
        stderr = " ".join((r.stderr or "").split())[:500]
        errors.append(
            f"AGENT_GUARD_FETCH_COMMAND exited {r.returncode}"
            + (f": {stderr}" if stderr else "")
        )
        LAST_RENDER_FETCH_ERROR = "; ".join(errors)
    node = shutil.which("node")
    if node is None:
        errors.append("node is not installed; cannot try Playwright render fetch")
        LAST_RENDER_FETCH_ERROR = "; ".join(errors)
        return None
    script = r"""
const { chromium } = require("playwright");
const url = process.argv[process.argv.length - 1];
(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    locale: "en-US",
  });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "networkidle", timeout: 60000 });
  await page.waitForTimeout(3000);
  const title = await page.title().catch(() => "");
  const text = await page.locator("body").innerText({ timeout: 5000 }).catch(() => "");
  const html = await page.content();
  console.log(`# Rendered marketplace page\n\nTitle: ${title}\nURL: ${page.url()}\n\n## Rendered text\n\n${text}\n\n## Rendered HTML\n\n${html}`);
  await browser.close();
})().catch((err) => {
  console.error(err && err.message ? err.message : String(err));
  process.exit(2);
});
"""
    with tempfile.TemporaryDirectory() as d:
        script_path = Path(d) / "render-marketplace.js"
        script_path.write_text(script, encoding="utf-8")
        commands = [[node, str(script_path), url]]
        npx = shutil.which("npx")
        if npx is not None:
            commands.append([
                npx, "--yes", "--package", "playwright",
                "node", "-e", script, url,
            ])
        for index, command in enumerate(commands):
            label = "Playwright render fetch" if index == 0 else "npx Playwright render fetch"
            try:
                r = subprocess.run(command, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=90)
            except subprocess.TimeoutExpired:
                errors.append(f"{label} timed out")
                continue
            except OSError as e:
                errors.append(f"{label} failed to start: {e}")
                continue
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout
            stderr = " ".join((r.stderr or "").split())[:500]
            if "Cannot find module 'playwright'" in stderr and index == 0:
                errors.append(
                    "Node is available, but the local playwright package is not installed"
                )
                continue
            if stderr:
                errors.append(f"{label} exited {r.returncode}: {stderr}")
            else:
                errors.append(f"{label} exited {r.returncode}")
        npm = shutil.which("npm")
        if npm is not None:
            try:
                install = subprocess.run(
                    [npm, "install", "--prefix", d, "playwright",
                     "--no-audit", "--no-fund"],
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=90,
                )
            except subprocess.TimeoutExpired:
                errors.append("temporary npm install playwright timed out")
            except OSError as e:
                errors.append(f"temporary npm install playwright failed to start: {e}")
            else:
                if install.returncode == 0:
                    try:
                        r = subprocess.run([node, str(script_path), url],
                                           capture_output=True, text=True,
                                           encoding="utf-8", errors="replace",
                                           timeout=90, cwd=d)
                    except subprocess.TimeoutExpired:
                        errors.append("temporary npm Playwright render fetch timed out")
                    except OSError as e:
                        errors.append(
                            f"temporary npm Playwright render fetch failed to start: {e}"
                        )
                    else:
                        if r.returncode == 0 and r.stdout.strip():
                            return r.stdout
                        stderr = " ".join((r.stderr or "").split())[:500]
                        errors.append(
                            "temporary npm Playwright render fetch exited "
                            f"{r.returncode}" + (f": {stderr}" if stderr else "")
                        )
                else:
                    stderr = " ".join((install.stderr or "").split())[:500]
                    errors.append(
                        f"temporary npm install playwright exited {install.returncode}"
                        + (f": {stderr}" if stderr else "")
                    )
    LAST_RENDER_FETCH_ERROR = "; ".join(errors)
    return None


def is_security_checkpoint(text: str) -> bool:
    lower = text.lower()
    return (
        "vercel security checkpoint" in lower
        or "enable javascript to continue" in lower
        or "we're verifying your browser" in lower
    )


def format_fetch_error(url: str, code: int, body: str) -> str:
    if code in {401, 403, 429} and is_security_checkpoint(body):
        return (
            f"could not fetch {url}: HTTP {code} from browser security checkpoint. "
            "No scan verdict is possible from this URL. Use a direct GitHub, "
            "archive, raw SKILL.md, npm, or PyPI source URL, or retry from an "
            "environment that can access the page without a JavaScript challenge."
        )
    if code == 429:
        return (
            f"could not fetch {url}: HTTP 429 rate-limited or bot-blocked by the "
            "marketplace. No scan verdict is possible from this URL right now."
        )
    return f"could not fetch {url}: HTTP {code}"


def safe_extract_tar(data: bytes, dest: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        try:
            tf.extractall(dest, filter="data")
            return
        except TypeError:
            pass
        root = dest.resolve()
        for m in tf.getmembers():
            p = (dest / m.name).resolve()
            if not str(p).startswith(str(root)):
                raise ValueError(f"unsafe path in archive: {m.name}")
            if m.issym() or m.islnk():
                raise ValueError(f"archive contains a link: {m.name}")
        tf.extractall(dest)


def safe_extract_zip(data: bytes, dest: Path) -> None:
    root = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            p = (dest / name).resolve()
            if not str(p).startswith(str(root)):
                raise ValueError(f"unsafe path in archive: {name}")
        zf.extractall(dest)


def first_child_dir(path: Path) -> Path:
    children = [p for p in path.iterdir() if p.is_dir()]
    return children[0] if len(children) == 1 else path


def github_repo_key(url: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(url.rstrip(".,;"))
    if parsed.netloc.lower() not in GITHUB_HOSTS:
        return None
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def github_parts(url: str) -> tuple[str, str, str | None, list[str]]:
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc.lower() not in GITHUB_HOSTS:
        raise ValueError("not a GitHub URL")
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError("GitHub URL must include owner/repo")
    owner, repo = parts[0], parts[1]
    ref = None
    subpath: list[str] = []
    if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
        ref = parts[3]
        subpath = parts[4:]
    return owner, repo.removesuffix(".git"), ref, subpath


def github_default_sha(owner: str, repo: str) -> str:
    meta = http_json(f"https://api.github.com/repos/{owner}/{repo}/commits/HEAD")
    return str(meta["sha"])


def github_ref_sha(owner: str, repo: str, ref: str) -> str:
    quoted = urllib.parse.quote(ref, safe="")
    try:
        meta = http_json(f"https://api.github.com/repos/{owner}/{repo}/commits/{quoted}")
        return str(meta["sha"])
    except Exception:
        return ref


def resolve_github(url: str, dest: Path) -> ResolvedSource:
    owner, repo, ref, subpath = github_parts(url)
    sha = github_ref_sha(owner, repo, ref) if ref else github_default_sha(owner, repo)
    archive = f"https://github.com/{owner}/{repo}/archive/{sha}.zip"
    safe_extract_zip(http_bytes(archive), dest)
    root = first_child_dir(dest)
    source = root.joinpath(*subpath) if subpath else root
    label = f"github:{owner}/{repo}@{sha}"
    if subpath:
        label += "/" + "/".join(subpath)
    return ResolvedSource(kind="github", source_path=source, label=label,
                          pinned_ref=sha,
                          install_hint=f"https://github.com/{owner}/{repo}@{sha}")


def resolve_archive(url: str, dest: Path) -> ResolvedSource:
    data = http_bytes(url)
    lower = urllib.parse.urlparse(url).path.lower()
    if lower.endswith(".zip"):
        safe_extract_zip(data, dest)
    elif lower.endswith((".tar.gz", ".tgz", ".tar")):
        safe_extract_tar(data, dest)
    else:
        raise ValueError("unsupported archive URL")
    return ResolvedSource(kind="archive", source_path=first_child_dir(dest),
                          label=url, pinned_ref="downloaded-archive")


def resolve_raw_markdown(url: str, dest: Path) -> ResolvedSource:
    data = http_bytes(url)
    path = dest / "downloaded.md"
    path.write_bytes(data)
    return ResolvedSource(kind="markdown", source_path=path, label=url,
                          pinned_ref="downloaded-file")


def extract_github_links_from_text(text: str) -> list[str]:
    seen: set[tuple[str, str]] = set()
    links: list[str] = []
    for match in GITHUB_LINK_RE.finditer(text):
        url = match.group(0).rstrip(".,;\\")
        key = github_repo_key(url)
        if key is None or key in seen:
            continue
        seen.add(key)
        links.append(url)
    return links


def clean_candidate_url(url: str) -> str:
    cleaned = html.unescape(url)
    for marker in ("\\n", "\\r", "```", "`"):
        if marker in cleaned:
            cleaned = cleaned.split(marker, 1)[0]
    cleaned = cleaned.strip().rstrip(".,;\\`'\"")
    cleaned = cleaned.removesuffix("&quot").removesuffix("&amp")
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.query and "YOUR_API_KEY" in parsed.query.upper():
        parsed = parsed._replace(query="")
    return urllib.parse.urlunparse(parsed)


def source_link_key(url: str) -> tuple[str, str] | None:
    url = clean_candidate_url(url)
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    parts = [p for p in path.strip("/").split("/") if p]
    if host in GITHUB_HOSTS:
        if len(parts) < 2:
            return None
        if (parts[0].lower(), parts[1].lower().removesuffix(".git")) in NON_SOURCE_GITHUB_REPOS:
            return None
        if len(parts) >= 3 and parts[2] not in {"tree", "blob"}:
            return None
        if len(parts) >= 3 and parts[2] == "blob":
            filename = parts[-1].lower()
            if filename not in {"skill.md", "pyproject.toml", "package.json"}:
                return None
        return github_repo_key(url)
    if host in {"www.npmjs.com", "npmjs.com"} and path.startswith("/package/"):
        return "npm", urllib.parse.unquote(path.removeprefix("/package/"))
    if host == "pypi.org" and path.startswith("/project/"):
        return "pypi", urllib.parse.unquote(path.removeprefix("/project/"))
    if path.lower().endswith((".zip", ".tar.gz", ".tgz", ".tar")):
        return "archive", url
    return None


def remote_mcp_key(url: str) -> tuple[str, str] | None:
    url = clean_candidate_url(url)
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    if host in GITHUB_HOSTS or host in {"www.npmjs.com", "npmjs.com", "pypi.org"}:
        return None
    if host.startswith("docs.") or host in {"docs.anthropic.com", "docs.continue.dev"}:
        return None
    path = parsed.path.rstrip("/").lower()
    if "/docs/" in path or "/documentation/" in path or "/customize/" in path:
        return None
    if path.endswith("/mcp") or path.endswith("/sse") or path in {"/mcp", "/sse"}:
        return "remote", urllib.parse.urlunparse(parsed._replace(query=""))
    return None


def extract_candidate_links_from_text(text: str) -> tuple[list[str], list[str]]:
    seen: set[tuple[str, str]] = set()
    source_links: list[str] = []
    remote_links: list[str] = []
    for match in URL_RE.finditer(text):
        url = clean_candidate_url(match.group(0))
        key = source_link_key(url)
        if key is None or key in seen:
            remote_key = remote_mcp_key(url)
            if remote_key is None or remote_key in seen:
                continue
            seen.add(remote_key)
            remote_links.append(remote_key[1])
            continue
        seen.add(key)
        source_links.append(url)
    return source_links, remote_links


INSTALL_COMMAND_RE = re.compile(
    r"(?m)^\s*(?:\$|>)?\s*((?:npx|uvx|docker|cargo)\s+[^\r\n`]+)"
)


def extract_install_commands(text: str) -> list[str]:
    commands: list[str] = []
    seen: set[str] = set()
    for match in INSTALL_COMMAND_RE.finditer(text):
        command = " ".join(match.group(1).strip().split())
        if command in seen:
            continue
        seen.add(command)
        commands.append(command)
    return commands


def compact_page_markdown(url: str, text: str) -> tuple[str, list[str], list[str], list[str]]:
    body = text
    if "<html" in text[:2000].lower() or "<!doctype html" in text[:2000].lower():
        parser = CompactHTMLText()
        parser.feed(text)
        body = parser.text()
    source_links, remote_links = extract_candidate_links_from_text(text)
    install_commands = extract_install_commands(text)
    if len(body) > 20000:
        body = body[:20000] + "\n\n[agent-guard: page text truncated for catalog scan]\n"
    source_block = "\n".join(f"- {link}" for link in source_links) or "- none"
    remote_block = "\n".join(f"- {link}" for link in remote_links) or "- none"
    command_block = "\n".join(f"- `{command}`" for command in install_commands) or "- none"
    markdown = (
        f"# Marketplace/catalog page\n\n"
        f"Source: {url}\n\n"
        f"## Extracted local/source candidate links\n\n{source_block}\n\n"
        f"## Extracted remote MCP candidate URLs\n\n{remote_block}\n\n"
        f"## Extracted install commands\n\n{command_block}\n\n"
        f"## Extracted page text\n\n{body}\n"
    )
    return markdown, source_links, remote_links, install_commands


def resolve_catalog_page(url: str, dest: Path) -> ResolvedSource:
    already_rendered = False
    try:
        data = http_bytes(url)
        text = data.decode("utf-8", errors="replace")
    except FetchError as original_error:
        rendered = fetch_rendered_page(url)
        if rendered is None:
            detail = f" Render fallback failed: {LAST_RENDER_FETCH_ERROR}" if LAST_RENDER_FETCH_ERROR else ""
            raise FetchError(f"{original_error}.{detail}") from original_error
        text = rendered
        already_rendered = True
    markdown, source_links, remote_links, install_commands = compact_page_markdown(url, text)
    if not already_rendered and not (source_links or remote_links or install_commands):
        # JS-heavy marketplaces often serve an empty app shell to plain HTTP
        # fetches; the real listing only exists after client-side rendering.
        rendered = fetch_rendered_page(url)
        if rendered is not None:
            candidate = compact_page_markdown(url, rendered)
            if candidate[1] or candidate[2] or candidate[3]:
                markdown, source_links, remote_links, install_commands = candidate
    page = dest / "catalog-page.md"
    page.write_text(markdown, encoding="utf-8")
    return ResolvedSource(kind="catalog", source_path=page, label=url,
                          pinned_ref="web-page", urls=source_links,
                          source_urls=source_links, remote_urls=remote_links,
                          install_commands=install_commands)


def package_from_url(url: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if host == "pypi.org" and len(parts) >= 2 and parts[0] == "project":
        return "pypi", parts[1]
    if host in {"www.npmjs.com", "npmjs.com"} and len(parts) >= 2 and parts[0] == "package":
        name = "/".join(parts[1:3]) if parts[1].startswith("@") and len(parts) >= 3 else parts[1]
        return "npm", name
    return None


def resolve_url(url: str, dest: Path) -> ResolvedSource:
    pkg = package_from_url(url)
    if pkg:
        return ResolvedSource(kind=pkg[0], label=url, install_hint=pkg[1])
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    if parsed.netloc.lower() in GITHUB_HOSTS:
        return resolve_github(url, dest)
    if path.endswith((".zip", ".tar.gz", ".tgz", ".tar")):
        return resolve_archive(url, dest)
    if path.endswith((".md", ".markdown")) or "raw.githubusercontent.com" in parsed.netloc.lower():
        return resolve_raw_markdown(url, dest)
    return resolve_catalog_page(url, dest)
