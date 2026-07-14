import os
import httpx

from services.observability.retry import async_retry
from services.reasoning.model_router import target_for

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:4b")


async def generate(prompt: str, system: str = None, format: str | dict = "json", agent: str = "reasoning") -> str:
    target = target_for(agent)
    payload = {
        "model": target.model,
        "prompt": prompt,
        "stream": False,
        # Qwen3 enables a hidden reasoning mode by default in some Ollama
        # versions. THOS needs the final structured answer, not an empty
        # visible response after an internal thinking pass.
        "think": False,
        # Without an explicit num_ctx, Ollama falls back to a small
        # default context window (often 2048), which silently truncates
        # long reasoning prompts (hypothesis + MITRE context + SIGMA rule
        # + a 10-record log sample) and/or the completion itself — this
        # was producing responses that cut off mid-sentence and never
        # closed their JSON. num_predict is bumped too so a genuinely
        # long structured answer (summary+findings+recommendations) has
        # room to finish instead of being cut off by an output cap.
        "options": {
            "num_ctx": target.num_ctx,
            "num_predict": target.num_predict,
        },
        # reasoning.py's SYSTEM_PROMPT asks for "Respond ONLY with a JSON
        # object" but nothing was enforcing that server-side, so the model
        # was free to reply conversationally (e.g. "Let's continue with
        # the analysis...") instead of JSON, which _extract_json then had
        # no valid structure to recover and fell back to the
        # "Could not parse structured findings" placeholder.
        #
        # A bare "format": "json" fixes THAT failure mode (guarantees
        # valid JSON syntax) but introduces a milder one: with no schema
        # to fill, a small model can satisfy the generic JSON grammar with
        # a mostly-empty object (missing/blank summary, findings,
        # recommendations), which is what produced the
        # "(no summary provided)" / "(no findings recorded)" placeholders
        # in report.py. Passing an explicit JSON Schema (a dict) instead
        # of the string "json" makes Ollama enforce the actual required
        # keys and types, so the model can no longer collapse to "{}" or
        # omit fields — callers that need a specific shape (like
        # reasoning.py) should pass their schema in via `format` rather
        # than relying on the "json" default.
        "format": format,
    }
    if system:
        payload["system"] = system

    async def _do_request():
        async with httpx.AsyncClient(timeout=float(os.environ.get("OLLAMA_GENERATION_TIMEOUT_SECONDS", "180"))) as client:
            resp = await client.post(f"{target.host}/api/generate", json=payload)
            resp.raise_for_status()
            body = resp.json()
            return str(body.get("response") or (body.get("message") or {}).get("content") or "").strip()

    # Reasoning prompts include hypothesis + MITRE context + SIGMA rule +
    # a log sample, so they're bigger than the query-gen prompt and take
    # noticeably longer to generate — especially on CPU-only inference or
    # right after the model was first pulled/loaded. 180s was too tight
    # and produced spurious httpx.ReadTimeout failures mid-hunt.
    # Local inference can be temporarily slow while Ollama loads a model;
    # retain the configurable retry policy for quality-sensitive hunts.
    retries = int(os.environ.get("OLLAMA_GENERATION_RETRIES", "3"))
    return await async_retry(_do_request, retries=retries, what="ollama_client.generate")
