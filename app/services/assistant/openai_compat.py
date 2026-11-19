"""OpenAI-style Chat Completions for the assistant (e.g. DeepSeek on Tencent TokenHub).

The assistant keeps its history in the Anthropic message format (what the
``deepseek`` and ``anthropic`` providers speak natively). For providers that
only offer ``/chat/completions`` this module translates that history on the
way out, streams the reply (text and tool-call fragments) and hands back a
message object with the same shape the agent loop reads: ``content`` blocks,
``stop_reason`` and ``usage``. The stored history stays in one format, so the
provider can be switched without losing conversations.

Same request style as the OVES Assets Assistant (lib/llm/client.ts there):
tools with tool_choice "auto", streaming, ``thinking`` / ``reasoning_effort``
only when configured, no temperature.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

STOP_REASONS = {
    "tool_calls": "tool_use",
    "function_call": "tool_use",
    "stop": "end_turn",
    "length": "max_tokens",
    "content_filter": "refusal",
}


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass
class Reply:
    content: list = field(default_factory=list)   # Anthropic-format block dicts
    stop_reason: Optional[str] = None
    usage: Usage = field(default_factory=Usage)


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def to_openai_messages(system: list[dict], messages: list[dict]) -> list[dict]:
    """Anthropic-format history -> Chat Completions messages."""
    out: list[dict] = [{"role": "system", "content": "".join(b.get("text", "") for b in system)}]
    for m in messages:
        blocks = m["content"] if isinstance(m["content"], list) else [{"type": "text", "text": m["content"]}]
        if m["role"] == "assistant":
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            reasoning = "".join(b.get("thinking", "") for b in blocks if b.get("type") == "thinking")
            calls = [
                {"id": b["id"], "type": "function",
                 "function": {"name": b["name"], "arguments": json.dumps(b.get("input") or {}, ensure_ascii=False)}}
                for b in blocks if b.get("type") == "tool_use"
            ]
            msg: dict = {"role": "assistant", "content": text or None}
            if calls:
                msg["tool_calls"] = calls
            if reasoning:
                # DeepSeek requires earlier reasoning back when tools are in use.
                msg["reasoning_content"] = reasoning
            out.append(msg)
            continue
        # user turn: tool results first (each its own "tool" message), then the rest
        for b in blocks:
            if b.get("type") == "tool_result":
                out.append({"role": "tool", "tool_call_id": b["tool_use_id"], "content": _text_of(b.get("content"))})
        parts: list[dict] = []
        for b in blocks:
            if b.get("type") == "text":
                parts.append({"type": "text", "text": b.get("text", "")})
            elif b.get("type") == "image":
                src = b.get("source") or {}
                if src.get("type") == "base64":
                    parts.append({"type": "image_url",
                                  "image_url": {"url": f"data:{src.get('media_type')};base64,{src.get('data')}"}})
                else:
                    parts.append({"type": "text", "text": "[A photo was sent here but is no longer available.]"})
        if parts:
            only_text = all(p["type"] == "text" for p in parts)
            out.append({"role": "user",
                        "content": "\n".join(p["text"] for p in parts) if only_text else parts})
    return out


def to_openai_tools(tools: list[dict]) -> list[dict]:
    return [{"type": "function",
             "function": {"name": t["name"], "description": t.get("description", ""),
                          "parameters": t["input_schema"]}} for t in tools]


async def stream_chat(*, base_url: str, api_key: str, model: str, system: list[dict],
                      messages: list[dict], tools: list[dict], max_tokens: int,
                      thinking: str = "", reasoning_effort: str = "",
                      on_text: Optional[Callable[[str], Awaitable[None]]] = None,
                      timeout: float = 180.0, transport: Optional[httpx.AsyncBaseTransport] = None) -> Reply:
    body: dict[str, Any] = {
        "model": model,
        "messages": to_openai_messages(system, messages),
        "tools": to_openai_tools(tools),
        "tool_choice": "auto",
        "stream": True,
        "stream_options": {"include_usage": True},
        "max_tokens": max_tokens,
    }
    if thinking in ("enabled", "disabled"):
        body["thinking"] = {"type": thinking}
    if reasoning_effort:
        body["reasoning_effort"] = reasoning_effort

    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    calls: dict[int, dict] = {}
    finish: Optional[str] = None
    usage = Usage()

    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        async with client.stream(
            "POST", f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Accept": "text/event-stream"},
            json=body,
        ) as response:
            if response.status_code >= 400:
                detail = (await response.aread()).decode("utf-8", "replace")[:400]
                raise RuntimeError(f"model API returned {response.status_code}: {detail}")
            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue  # keep-alive comments, blank lines
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    chunk = json.loads(data)
                except ValueError:
                    continue
                if "error" in chunk and not chunk.get("choices"):
                    raise RuntimeError(f"model API error: {str(chunk['error'])[:300]}")
                if chunk.get("usage"):
                    u = chunk["usage"]
                    hit = int(u.get("prompt_cache_hit_tokens")
                              or (u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
                    usage = Usage(input_tokens=max(0, int(u.get("prompt_tokens") or 0) - hit),
                                  output_tokens=int(u.get("completion_tokens") or 0),
                                  cache_read_input_tokens=hit)
                for choice in chunk.get("choices") or []:
                    delta = choice.get("delta") or {}
                    if delta.get("reasoning_content"):
                        reasoning_parts.append(delta["reasoning_content"])
                    if delta.get("content"):
                        text_parts.append(delta["content"])
                        if on_text is not None:
                            await on_text(delta["content"])
                    for tc in delta.get("tool_calls") or []:
                        slot = calls.setdefault(int(tc.get("index", 0)), {"id": "", "name": "", "arguments": ""})
                        if tc.get("id"):
                            slot["id"] = tc["id"]
                        fn = tc.get("function") or {}
                        if fn.get("name"):
                            slot["name"] = fn["name"]
                        if fn.get("arguments"):
                            slot["arguments"] += fn["arguments"]
                    if choice.get("finish_reason"):
                        finish = choice["finish_reason"]

    content: list[dict] = []
    if reasoning_parts:
        content.append({"type": "thinking", "thinking": "".join(reasoning_parts), "signature": ""})
    if text_parts:
        content.append({"type": "text", "text": "".join(text_parts)})
    for i in sorted(calls):
        call = calls[i]
        try:
            args = json.loads(call["arguments"]) if call["arguments"].strip() else {}
            if not isinstance(args, dict):
                args = {"_invalid_arguments": call["arguments"][:2000]}
        except ValueError:
            args = {"_invalid_arguments": call["arguments"][:2000]}
        content.append({"type": "tool_use", "id": call["id"] or f"call_{i}", "name": call["name"], "input": args})
    stop = STOP_REASONS.get(finish or "", "end_turn")
    if calls and stop == "end_turn":
        stop = "tool_use"
    return Reply(content=content, stop_reason=stop, usage=usage)
