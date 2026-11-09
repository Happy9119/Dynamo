import os
import time
import json
import hashlib
import requests
import traceback
from typing import Optional

from schemas.asset import Asset, AIIntelligence, AIResult
from ai.ai_prompts import build_asset_analysis_prompt
from config.tools import TRIAGE_MODEL, DEEP_MODEL
from config.runtime import get_model_for_task
from storage.database import SessionLocal
from storage.models import AICacheModel

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

OLLAMA_ENDPOINT = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
REQUEST_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "900"))
KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")


def _get_cache_key(asset: Asset, task: str, model: str, prompt: str) -> str:
    svc_sig = sorted(
        (s.port, s.protocol, s.product or "", s.version or "")
        for s in asset.services
    )
    cve_sig = sorted(
        (c.get("cve") or "", c.get("severity") or "")
        for c in asset.cves
    )
    vuln_sig = sorted(
        (getattr(v, "vuln_type", "") or "",
         getattr(v, "url", "") or "",
         getattr(v, "severity", "") or "")
        for v in (asset.vulns or [])
    )
    nuclei_sig = sorted(
        (getattr(f, "template_id", "") or "",
         getattr(f, "matched_at", "") or "")
        for f in (asset.nuclei_findings or [])
    )
    sqli_sig = sorted(
        (getattr(s, "url", "") or "")
        for s in (asset.sqli_findings or [])
    )
    tech_sig = sorted(asset.technologies or [])

    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:12]

    sig = (
        f"{asset.asset_value}|{svc_sig}|{cve_sig}|{vuln_sig}|"
        f"{nuclei_sig}|{sqli_sig}|{tech_sig}|{task}|{model}|{prompt_hash}"
    )
    return hashlib.sha256(sig.encode()).hexdigest()


def _close_json(text):
    stack = []
    in_string = False
    escape = False
    for c in text:
        if escape:
            escape = False
            continue
        if in_string:
            if c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c == "{":
            stack.append("}")
        elif c == "[":
            stack.append("]")
        elif c == "}":
            if stack and stack[-1] == "}":
                stack.pop()
            else:
                return None
        elif c == "]":
            if stack and stack[-1] == "]":
                stack.pop()
            else:
                return None
    result = text
    if in_string:
        result += '"'
    result += "".join(reversed(stack))
    return result


def _attempt(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        return json.loads(text, strict=False)
    except Exception:
        pass
    balanced = _close_json(text)
    if balanced and balanced != text:
        try:
            return json.loads(balanced, strict=False)
        except Exception:
            pass
    return None


def _try_parse_json(raw):
    if not raw:
        return None

    text = raw.strip()
    result = _attempt(text)
    if result is not None:
        return result

    if text.startswith("```"):
        lines = text.split("\n")
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
        result = _attempt(text)
        if result is not None:
            return result

    start = text.find("{")
    if start == -1:
        return None
    text = text[start:]

    result = _attempt(text)
    if result is not None:
        return result

    n = len(text)
    attempts = 0
    max_attempts = 200
    for cut in range(n - 1, -1, -1):
        c = text[cut]
        if c not in ',}]"0123456789':
            continue
        snippet = text[:cut + 1].rstrip()
        if snippet.endswith(","):
            snippet = snippet[:-1]
        
        if len(snippet) < (len(text) * 0.5):
            return None
            
        result = _attempt(snippet)
        if result is not None:
            return result
        attempts += 1
        if attempts >= max_attempts:
            break

    return None


def explain_finding(finding_text: str, asset_context: str) -> str:
    """Lightweight endpoint for the UI to ask about a single finding."""
    prompt = (
        f"You are an expert penetration tester. Explain this vulnerability to me.\n"
        f"Context: {asset_context}\n"
        f"Finding: {finding_text}\n\n"
        f"Provide a concise explanation of how to exploit it and how to fix it. Keep it under 150 words."
    )
    try:
        payload = {
            "model": get_model_for_task("triage"),
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 300}
        }
        res = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=60)
        return res.json().get("response", "AI failed to respond.").strip()
    except Exception as e:
        return f"Error: {str(e)}"


def generate_asset_intelligence(asset: Asset, task="deep") -> Optional[AIResult]:
    started = time.perf_counter()

    model = get_model_for_task(task)
    prompt = build_asset_analysis_prompt(asset)
    cache_key = _get_cache_key(asset, task, model, prompt)

    session = SessionLocal()
    try:
        cached = session.query(AICacheModel).filter_by(asset_hash=cache_key, task=task).first()
        if cached:
            intel = AIIntelligence(**json.loads(cached.response_json))
            return AIResult(
                status="success", 
                model="cache", 
                latency_ms=0, 
                intelligence=intel
            )
    except Exception:
        pass
    finally:
        session.close()

    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": AIIntelligence.model_json_schema(),
            "keep_alive": KEEP_ALIVE,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 2500,
                "repeat_penalty": 1.05,
            },
        }

        response = requests.post(OLLAMA_ENDPOINT, json=payload, timeout=REQUEST_TIMEOUT)

        if response.status_code != 200:
            return AIResult(
                status="http_error",
                model=model,
                latency_ms=int((time.perf_counter() - started) * 1000),
                error=f"status {response.status_code}",
            )

        raw_response = response.json().get("response", "")
        parsed = _try_parse_json(raw_response)

        if parsed is None:
            head = (raw_response or "")[:250].replace("\n", " ")
            tail = (raw_response or "")[-250:].replace("\n", " ")
            return AIResult(
                status="invalid_json",
                model=model,
                latency_ms=int((time.perf_counter() - started) * 1000),
                error=(
                    f"unparseable ({len(raw_response or '')} chars) "
                    f"| HEAD: {head} | TAIL: {tail}"
                ),
            )

        try:
            intel = AIIntelligence(**parsed)
        except Exception as ve:
            return AIResult(
                status="schema_error",
                model=model,
                latency_ms=int((time.perf_counter() - started) * 1000),
                error=f"schema validation failed: {str(ve)[:200]}",
            )

        # 3. Save to Cache
        session = SessionLocal()
        try:
            session.add(AICacheModel(
                asset_hash=cache_key, 
                task=task, 
                response_json=intel.model_dump_json()
            ))
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

        return AIResult(
            status="success",
            model=model,
            latency_ms=int((time.perf_counter() - started) * 1000),
            intelligence=intel,
        )

    except requests.Timeout as e:
        return AIResult(status="timeout", model=model,
                        latency_ms=int((time.perf_counter() - started) * 1000),
                        error=str(e))
    except requests.RequestException as e:
        return AIResult(status="unavailable", model=model, error=str(e))
    except Exception as e:
        tb = traceback.format_exc()
        print(f"[!] ai_engine uncaught exception:\n{tb}")
        return AIResult(
            status="error",
            model=model,
            error=f"{type(e).__name__}: {e}",
        )