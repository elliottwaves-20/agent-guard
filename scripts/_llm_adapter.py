"""Process-local SkillSpector adapter (exact version: _llm_budget.POLICY); upstream files are never edited."""
from __future__ import annotations

import asyncio
import contextvars
import importlib.metadata
import json
import os
import sys
import urllib.error
import urllib.request
from types import SimpleNamespace

from _llm_budget import MODEL, POLICY, Paused

CONTEXT = contextvars.ContextVar("guard_batch", default={"analyzer": "chat_completion"})
BASE_URL = "https://api.cerebras.ai/v1"


class ProviderError(RuntimeError):
    def __init__(self, status_code, retry_after=60):
        super().__init__(f"Provider HTTP {status_code}")
        self.status_code, self.retry_after = status_code, retry_after


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_json(url, payload=None, key=None):
    headers = {"Content-Type": "application/json", "User-Agent": "agent-guard/0.3.1"}
    if key:
        headers["Authorization"] = "Bearer " + key
    request = urllib.request.Request(url, data=None if payload is None else
                                     json.dumps(payload).encode("utf-8"), headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise Paused("Provider response exceeds size limit")
            return json.loads(raw), dict(response.headers)
    except urllib.error.HTTPError as exc:
        retry = exc.headers.get("Retry-After", "60")
        try:
            retry = max(60, float(retry))
        except ValueError:
            from email.utils import parsedate_to_datetime
            import time
            try:
                retry = max(60, parsedate_to_datetime(retry).timestamp() - time.time())
            except (ValueError, TypeError):
                retry = 60
        raise ProviderError(exc.code, retry) from None


def live_transport():
    key = os.environ.get("CEREBRAS_API_KEY", "").strip()
    if not key:
        raise Paused("CEREBRAS_API_KEY is missing; no model request sent")
    info, _ = http_json("https://api.cerebras.ai/public/v1/models/" + MODEL)
    from decimal import Decimal
    if (info.get("id") != MODEL or info.get("deprecated") is not False
            or Decimal(info["pricing"]["prompt"]) * 10**9 != POLICY["input_nusd"]
            or Decimal(info["pricing"]["completion"]) * 10**9 != POLICY["output_nusd"]
            or not info.get("capabilities", {}).get("structured_outputs")):
        raise Paused("Model availability/pricing changed; review required")
    return lambda payload: http_json(BASE_URL + "/chat/completions", payload, key)


def strict_schema(schema):
    schema = json.loads(json.dumps(schema))
    def visit(node):
        if isinstance(node, dict):
            node.pop("default", None)
            if node.get("type") == "object" and "properties" in node:
                node["additionalProperties"] = False
                node["required"] = list(node["properties"])
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)
    visit(schema)
    return schema


class Model:
    def __init__(self, budget, schema=None):
        self.budget, self.schema = budget, schema
        self.model_name = MODEL

    def with_structured_output(self, schema):
        return Model(self.budget, schema)

    def invoke_with_usage(self, prompt, collector=None):
        if not isinstance(prompt, str):
            raise Paused("Unsupported scanner prompt type")
        payload = {"model": MODEL, "messages": [{"role": "user", "content": prompt}],
                   "max_completion_tokens": POLICY["output_tokens"], "stream": False}
        if self.schema:
            payload["response_format"] = {"type": "json_schema", "json_schema": {
                "name": self.schema.__name__, "strict": True,
                "schema": strict_schema(self.schema.model_json_schema())}}
        def validate(content):
            if not isinstance(content, str):
                raise Paused("Missing textual response")
            if self.schema:
                return self.schema.model_validate_json(content)
            from langchain_core.messages import AIMessage
            return AIMessage(content=content)
        result, usage = self.budget.call(payload, CONTEXT.get(), validate)
        if collector:
            collector.mark_response_received()
        return result

    def invoke(self, prompt):
        return self.invoke_with_usage(prompt)

    async def ainvoke_with_usage(self, prompt, collector=None):
        return await asyncio.to_thread(self.invoke_with_usage, prompt, collector)

    async def ainvoke(self, prompt):
        return await self.ainvoke_with_usage(prompt)


def install(budget):
    """Install before importing graph/nodes, to cover imported factory aliases."""
    if importlib.metadata.version("skillspector") != POLICY["scanner"]:
        raise Paused("Budget adapter requires exactly SkillSpector " + POLICY["scanner"])
    for key in list(os.environ):
        if key.startswith("SKILLSPECTOR_"):
            del os.environ[key]
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ.update(SKILLSPECTOR_PROVIDER="openai_compatible", SKILLSPECTOR_MODEL=MODEL,
                      SKILLSPECTOR_COMPAT_BASE_URL=BASE_URL,
                      SKILLSPECTOR_MAX_LLM_CONCURRENCY="1",
                      SKILLSPECTOR_MAX_WORKFLOW_SECONDS="540",
                      AGENT_GUARD_LLM_RETRIES="0", AGENT_GUARD_NO_DOTENV="1")
    # No credential is handed to upstream. Only our HTTP transport receives it.
    # Upstream constructs its graph during package import and checks whether a
    # credential exists. A non-secret sentinel keeps analyzers enabled; their
    # factories are all replaced below before the graph can execute.
    os.environ["SKILLSPECTOR_COMPAT_API_KEY"] = "guard-transport-only-not-a-key"
    import skillspector.llm_utils as utils
    import skillspector.model_info as model_info
    original_input = model_info.get_max_input_tokens
    original_output = model_info.get_max_output_tokens
    original_factory, original_available = utils.get_chat_model, utils.is_llm_available
    def factory(*args, **kwargs):
        model = Model(budget)
        utils.register_chat_model_provider(model, "cerebras")
        return model
    utils.get_chat_model = factory
    utils.is_llm_available = lambda: (True, None)
    for module in list(sys.modules.values()):
        if module is not None and getattr(module, "__name__", "").startswith("skillspector"):
            for name, value in list(vars(module).items()):
                if value is original_factory:
                    setattr(module, name, factory)
                elif value is original_available:
                    setattr(module, name, utils.is_llm_available)
                elif value is original_input:
                    setattr(module, name, lambda *args, **kwargs: 4000)
                elif value is original_output:
                    setattr(module, name, lambda *args, **kwargs: POLICY["output_tokens"])
    # Disable alternate factory routes rather than permitting an unbudgeted fallback.
    def forbidden(*args, **kwargs):
        raise Paused("Unbudgeted provider route refused")
    utils.create_chat_model = forbidden
    utils.create_chat_model_with_provider = forbidden
    import skillspector.providers as providers
    providers.create_chat_model = forbidden
    providers.create_chat_model_with_provider = forbidden
    from skillspector.providers.openai_compatible.provider import OpenAICompatibleProvider
    OpenAICompatibleProvider.create_chat_model = forbidden
    import skillspector.llm_analyzer_base as base
    base.get_chat_model = factory
    base.API_CONNECTION_MAX_RETRIES = 0
    base.API_CONNECTION_RETRY_DELAYS_SECONDS = ()
    base.STRUCTURED_RESPONSE_MAX_ATTEMPTS = 1
    base.STRUCTURED_RESPONSE_MAX_RETRIES = 0
    base.LLM_BATCH_MAX_ATTEMPTS = 1
    cls = base.LLMAnalyzerBase
    original_init = cls.__init__
    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._guard_node = kwargs.get("node", "llm_analyzer")
        # Smaller file chunks leave room for line numbering and response schema.
        self._input_budget = 4000
    cls.__init__ = init
    original_sync, original_async = cls._invoke_batch, cls._ainvoke_batch
    def context(self, batch):
        return {"analyzer": self._guard_node, "file": batch.file_path,
                "start_line": batch.start_line, "end_line": batch.end_line}
    def invoke(self, batch, prompt):
        token = CONTEXT.set(context(self, batch))
        try:
            return original_sync(self, batch, prompt)
        finally:
            CONTEXT.reset(token)
    async def ainvoke(self, batch, prompt):
        token = CONTEXT.set(context(self, batch))
        try:
            return await original_async(self, batch, prompt)
        finally:
            CONTEXT.reset(token)
    cls._invoke_batch, cls._ainvoke_batch = invoke, ainvoke
