# Changelog

## 0.2.0 - 2026-06-15

- Add provider-aware `scan_skill.py` wrapper for skill scans.
- Share SkillSpector static-scan verdict logic between skill scans and MCP Stage 1.
- Require OpenAI or NVIDIA credentials for full SkillSpector LLM coverage.
- Separate Cisco runtime MCP LLM configuration via `MCP_SCANNER_LLM_*`; Cisco can use any LiteLLM-supported provider.
- Document that Anthropic under SkillSpector runs static-only in this pinned integration, while Cisco runtime provider choice is independent.
