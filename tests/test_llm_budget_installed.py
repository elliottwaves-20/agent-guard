"""Opt-in installed-scanner contract tests. All model responses are simulated."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from llm_scan import new_session

DRIVER = r'''
import json, sys, socket
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from _llm_adapter import http_json
import _llm_adapter
from llm_scan import scan
def refuse(*args, **kwargs):
    raise AssertionError("No network is allowed in installed contract tests")
original_connect = socket.socket.connect
def local_only(self, address):
    # Windows asyncio uses a loopback socket pair internally.
    if isinstance(address, tuple) and address[0] in ("127.0.0.1", "::1"):
        return original_connect(self, address)
    return refuse(address)
socket.socket.connect = local_only
_llm_adapter.http_json = refuse
def minimal(node, root):
    if "$ref" in node:
        target = root
        for name in node["$ref"].split("/")[1:]: target = target[name]
        return minimal(target, root)
    if "enum" in node: return node["enum"][0]
    if "anyOf" in node: return minimal(node["anyOf"][0], root)
    kind = node.get("type")
    if kind == "object": return {k: minimal(v, root) for k,v in node.get("properties",{}).items()}
    if kind == "array": return []
    if kind == "boolean": return False
    if kind in ("number", "integer"): return node.get("minimum", 0)
    if kind == "null": return None
    return ""
def transport(payload):
    assert "tools" not in payload
    schema = payload["response_format"]["json_schema"]["schema"]
    content = json.dumps(minimal(schema, schema))
    return {"choices":[{"finish_reason":"stop","message":{"content":content}}],
            "usage":{"prompt_tokens":100,"completion_tokens":20}}, {}
_llm_adapter.live_transport = lambda: transport
raise SystemExit(scan(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "preview"))
'''


@unittest.skipUnless(os.environ.get("AGENT_GUARD_BUDGET_CONTRACT") == "1",
                     "set AGENT_GUARD_BUDGET_CONTRACT=1 with installed scanner Python; no live calls")
class InstalledBudgetContract(unittest.TestCase):
    def test_preview_probe_resume_preserves_all_semantic_analyzers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            (target / "SKILL.md").write_text("---\nname: greeting\ndescription: Greet the user politely.\n---\n\n# Greeting\nSay hello to the user.\n")
            campaign = root / "campaign"
            session = new_session(target, campaign)
            scripts = str(Path(__file__).resolve().parents[1] / "scripts")
            def invoke(mode):
                result = subprocess.run([sys.executable, "-c", DRIVER, scripts, str(session), str(campaign), mode],
                                        capture_output=True, text=True, timeout=90)
                self.assertIn(result.returncode, (0, 1, 2), result.stderr[-4000:])
                return result
            preview = invoke("preview")
            plan = json.loads((session / "plan.json").read_text())
            self.assertEqual(plan["requests_total"], 0)
            self.assertTrue({"semantic_security_discovery", "semantic_developer_intent", "semantic_quality_policy"}
                            <= {p["analyzer"] for p in plan["prompts"]},
                            repr(plan) + preview.stderr[-5000:] + preview.stdout[-2000:])
            self.assertFalse((campaign / "budget.json").exists())
            invoke("live")
            progress = json.loads((session / "progress.json").read_text())
            self.assertEqual(progress["requests_total"], 1)
            self.assertFalse(progress["complete"])
            invoke("live")
            progress = json.loads((session / "progress.json").read_text())
            self.assertTrue(all(p["state"] in ("complete", "cached") for p in progress["prompts"]), progress)
            self.assertTrue(any(p["state"] == "cached" for p in progress["prompts"]), progress)
            ledger = json.loads((campaign / "budget.json").read_text())
            self.assertEqual(len({a["id"] for a in ledger["attempts"]}), len(ledger["attempts"]))
            report = json.loads((session / "report.json").read_text())
            self.assertEqual(report["metadata"]["llm_calls_attempted"], report["metadata"]["llm_calls_succeeded"])


if __name__ == "__main__":
    unittest.main()
