---
name: skill-scanner
description: >
  Security scanner for Claude Code Skills and MCP servers using cisco-ai-skill-scanner.
  Use this skill whenever the user: provides a GitHub URL for a skill or MCP to install,
  asks to scan or check if a skill/MCP is safe, wants to audit installed skills,
  says "überprüfe", "scanne", "ist das sicher", "check this skill", "scan before install",
  or any variation of wanting to verify a skill or plugin before or after installation.
  Always invoke this skill proactively when a GitHub URL for a skill/plugin is given — do
  not install anything without scanning first.
---

## Zweck

Sicherheitsprüfung von Skills und MCP-Servern mit `cisco-ai-skill-scanner` (v2.0.11).
Ziel: Bedrohungen erkennen, bevor ein Skill installiert wird oder alle installierten Skills auditieren.

## Setup

**Binary-Pfad:** `/c/Users/illia/.local/bin/skill-scanner` (via `uv tool install`, nur in Git Bash erreichbar)

**API-Key laden** (vor jedem Scan):
```bash
set -a && source /c/Users/illia/OneDrive/Dokumente/Github/.env && set +a
```

Die `.env` enthält `SKILL_SCANNER_LLM_API_KEY` und `SKILL_SCANNER_LLM_MODEL` für den Anthropic-Analyzer.

## Scan-Modi

### 1. GitHub-URL scannen (vor Installation)

> **Sicherheitsregel:** Niemals `git clone` für unbekannte Repos — Git führt `.git/hooks/`
> automatisch aus. Stattdessen **immer ZIP-Download** verwenden. Kein Hook, kein Autostart.

```bash
# ZIP herunterladen (keine Git-Hooks)
REPO_NAME=$(basename <github-url> .git)
curl -sL "https://github.com/<USER>/<REPO>/archive/refs/heads/main.zip" \
  -o /tmp/${REPO_NAME}-scan.zip
unzip -q /tmp/${REPO_NAME}-scan.zip -d /tmp/${REPO_NAME}-scan/
```

GitHub-URLs haben das Format `https://github.com/USER/REPO` → ZIP-URL:
`https://github.com/USER/REPO/archive/refs/heads/main.zip`

```bash
# Skill-Pfad bestimmen (SKILL.md suchen)
find /tmp/${REPO_NAME}-scan -name "SKILL.md" | grep -v node_modules

# Scan ausführen
set -a && source /c/Users/illia/OneDrive/Dokumente/Github/.env && set +a
skill-scanner scan "/tmp/${REPO_NAME}-scan/<skill-pfad>" \
  --use-behavioral --use-llm --llm-provider anthropic --enable-meta \
  --format table 2>/dev/null

# Cleanup — immer, egal ob SAFE oder nicht
rm -rf /tmp/${REPO_NAME}-scan /tmp/${REPO_NAME}-scan.zip
```

Falls das Repo mehrere Skills enthält:
```bash
skill-scanner scan-all "/tmp/${REPO_NAME}-scan" --use-behavioral \
  --use-llm --llm-provider anthropic --enable-meta --format table 2>/dev/null
```

### 2. Alle installierten Skills scannen

Erst echte Skill-Verzeichnisse sammeln (node_modules ausschließen):
```bash
find /c/Users/illia/.claude/plugins/cache -name "SKILL.md" \
  | grep -v "node_modules" \
  | xargs -I{} dirname {} | sort -u
```

Dann pro Plugin-`skills/`-Verzeichnis:
```bash
set -a && source /c/Users/illia/OneDrive/Dokumente/Github/.env && set +a
skill-scanner scan-all "<plugin>/skills" --use-behavioral --format table 2>/dev/null
```

**Nicht** `--recursive` auf den gesamten Plugin-Cache anwenden — `node_modules` macht den Scan nie fertig.

### 3. Lokalen Pfad scannen

```bash
set -a && source /c/Users/illia/OneDrive/Dokumente-Github/.env && set +a
skill-scanner scan "<pfad>" --use-behavioral --use-llm --llm-provider anthropic \
  --enable-meta --format table 2>/dev/null
```

## Ergebnis interpretieren

### Severity-Stufen

| Severity | Bedeutung | Empfehlung |
|----------|-----------|------------|
| CRITICAL | Klare Bedrohung (Exfiltration, Injection) | Nicht installieren |
| HIGH | Wahrscheinliche Bedrohung | Quellcode prüfen, dann entscheiden |
| MEDIUM | Strukturelle Risiken, Code-Patterns | Kontext prüfen (oft False Positive) |
| LOW | Fehlende Metadaten, Policy-Verstöße | Ignorierbar |
| INFO | Lizenz fehlt, Stil-Hinweise | Ignorierbar |

### Status-Bedeutung

- `[OK] SAFE` + Max Severity ≤ MEDIUM → **Installieren ist safe**
- `[FAIL] ISSUES` + HIGH/CRITICAL → **Quellcode manuell prüfen**

### Bekannte False Positives

Skills aus diesen offiziellen Quellen können als vertrauenswürdig behandelt werden:
- **superpowers** (claude-plugins-official)
- **firecrawl** (claude-plugins-official)
- **brightdata** / brightdata-plugin
- **skill-creator** (claude-plugins-official)
- **caveman** — `compress`-Skill: HIGH-Finding ist FP (Code *verhindert* Credential-Zugriff aktiv)
- **chrome-devtools-mcp** — `memory-leak-debugging`: MEDIUM ist FP (Policy-Hinweis)

### Typische False-Positive-Muster

- **Capability Inflation**: Skill-Beschreibung zu weit formuliert → kein echtes Risiko
- **Credential file access detected**: Code der Credentials *blockiert* → Quellcode prüfen
- **Command Injection in scaffold.sh**: Bash-Skripte die Dateien erstellen → by design
- **Tool Exploitation - Unrestricted File System Access**: Scaffold-Tools → by design

## Verdikt ausgeben

Nach dem Scan immer klar kommunizieren:

```
✅ SAFE — kein Critical/High. Installieren empfohlen.
   Findings: [Medium/Low/Info mit Kurzbeschreibung]

⚠️ PRÜFEN ERFORDERLICH — [Anzahl] High-Findings.
   Betroffene Datei: [Pfad:Zeile]
   Befund: [was genau gefunden wurde]
   → Quellcode lesen, dann entscheiden.

🚫 NICHT INSTALLIEREN — Critical-Finding.
   Grund: [konkreter Befund]
```

## MCP-Isolationsregeln (vor jeder Installation beachten)

Kein MCP-Server darf globale Python-Abhängigkeiten installieren. Immer isoliert:

| Quelle | Befehl | Config-Eintrag |
|--------|--------|----------------|
| PyPI (eigener MCP-Entrypoint) | `uvx paketname` | `{"command":"uvx","args":["paketname"]}` |
| PyPI (Modul-Start) | `uv run --with dep1 --with dep2 python -m modul` | je Dep ein eigenes `--with`-Flag |
| GitHub (nicht PyPI) | `uv tool install --from "git+URL" name` in PowerShell | Pfad: `%APPDATA%\uv\tools\NAME\Scripts\NAME.exe` |
| npm | `npx --silent -y paketname` | `{"command":"npx","args":["--silent","-y","paket"]}` |
| Remote/HTTP | URL direkt in Config | kein lokaler Code nötig |

**OneDrive-Pfade + uv:** Immer `--link-mode=copy` verwenden:
```bash
uv tool install paketname --link-mode=copy
```

**Nie:** `pip install` für MCP-Dependencies. Nie globale Node-Module wenn `npx` reicht.

Lokale MCP-Repos werden ausschließlich hier abgelegt:
```
%USERPROFILE%\OneDrive\Dokumente\Github\<repo-name>\
```

## Installations-Workflow (nach SAFE-Verdikt)

Nach SAFE-Verdikt: Universal-Installer nutzen — installiert automatisch für
**Claude Code, Claude Desktop, Codex** (und Antigravity sobald Pfad konfiguriert).

### Installer (portabel — erkennt installierte Tools automatisch)

Der Installer verwendet keine hardcodierten Pfade. Er erkennt welche Tools auf dem
jeweiligen System installiert sind und schreibt nur in vorhandene Configs:

| Tool | Erkennungspfad |
|------|---------------|
| Claude Code | `~/.claude/` |
| Claude Desktop | `%APPDATA%/Claude/claude_desktop_config.json` |
| Codex | `~/.codex/config.toml` |
| Antigravity | `~/.gemini/config/mcp_config.json` |

```bash
# Installer-Pfad (einmal merken)
INSTALLER="$HOME/.claude/skills/skill-scanner/scripts/install_skill.py"
```

### Skill installieren (markdown, keine Executables)

```bash
# 1. Erst nach SAFE-Verdikt: git clone
git clone --depth=1 <url> "$HOME/OneDrive/Dokumente/Github/<name>"

# 2. Universal-Installer (erkennt Tools automatisch)
python "$INSTALLER" skill "$HOME/OneDrive/Dokumente/Github/<name>"

# Anderen Workspace angeben (optional):
python "$INSTALLER" skill <pfad> --workspace /pfad/zum/workspace
```

Erstellt Symlinks nur wo vorhanden:
- `~/.claude/skills/<name>` (wenn Claude Code installiert)
- `~/.codex/skills/<name>` (wenn Codex installiert)

Update: `cd <workspace>/<name> && git pull`

### MCP installieren

```bash
python "$INSTALLER" mcp \
  --name "server-name" \
  --command "uvx" \
  --args "paketname" \
  --env "API_KEY=xyz"
```

Schreibt automatisch in alle erkannten Tools. Dry-run immer zuerst:
```bash
python "$INSTALLER" mcp --name foo --command uvx --args bar --dry-run
python "$INSTALLER" skill <pfad> --dry-run
```

### Auf anderen Maschinen / anderen Usern

Kein Anpassen nötig — der Installer nutzt `HOME` und `APPDATA` aus der Umgebung.
Nur `--workspace` anpassen wenn der Repo-Ordner abweicht:
```bash
python "$INSTALLER" skill <pfad> --workspace "D:/Projekte/Github"
```

## Analyzer-Optionen

| Flag | Wann nutzen |
|------|-------------|
| `--use-behavioral` | Immer (dataflow analysis, kostenlos) |
| `--use-llm --llm-provider anthropic` | Für tiefere semantische Analyse (kostet API-Credits) |
| `--enable-meta` | Mit LLM kombinieren — filtert False Positives automatisch |
| `--format table` | Standard-Output |
| `--format html --output report.html` | Interaktiver Bericht für komplexe Findings |
