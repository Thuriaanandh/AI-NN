# backend/app.py
from dotenv import load_dotenv
load_dotenv()

import os, tempfile, subprocess, json, time, sys, logging, hashlib
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict
from transformers import pipeline
from huggingface_hub import InferenceClient

# -------------------------
# Logging setup
# -------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ai-code-scanner")
CACHE = {}

def cache_key(code, filename, language):
    h = hashlib.sha256((language + filename + code).encode("utf-8")).hexdigest()
    return h

# -------------------------
# Gemini client (optional)
# -------------------------
try:
    from google import genai
    GEMINI_AVAILABLE = True
except Exception:
    GEMINI_AVAILABLE = False
    genai = None

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_AVAILABLE and GEMINI_API_KEY:
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("✅ Gemini client initialized")
    except Exception as e:
        gemini_client = None
        logger.warning(f"⚠️ Gemini init failed: {e}")
else:
    gemini_client = None
    logger.warning("⚠️ Gemini not available or API key missing")

# -------------------------
# FastAPI app
# -------------------------
app = FastAPI()

# -------------------------
# Hugging Face model
# -------------------------
HF_MODEL = "mrm8488/codebert-base-finetuned-detect-insecure-code"
classifier = None
use_hf_inference_api = False
hf_inference_client = None

HF_API_TOKEN = os.getenv("HF_API_TOKEN")
if HF_API_TOKEN:
    try:
        hf_inference_client = InferenceClient(token=HF_API_TOKEN)
        use_hf_inference_api = True
        logger.info("✅ Using Hugging Face Inference API")
    except Exception as e:
        logger.warning(f"⚠️ HF Inference API init failed: {e}")
        use_hf_inference_api = False

if not use_hf_inference_api:
    try:
        classifier = pipeline("text-classification", model=HF_MODEL, tokenizer=HF_MODEL)
        logger.info("✅ Loaded local Hugging Face model")
    except Exception as e:
        logger.warning(f"⚠️ Local HF load failed: {e}")
        classifier = None
        if HF_API_TOKEN:
            try:
                hf_inference_client = InferenceClient(token=HF_API_TOKEN)
                use_hf_inference_api = True
            except Exception:
                use_hf_inference_api = False

# -------------------------
# Request schema
# -------------------------
class AnalyzeReq(BaseModel):
    language: str
    filename: str
    code: str

# -------------------------
# Normalize Semgrep output
# -------------------------
def _normalize_semgrep_item(item: Dict) -> Dict:
    start = item.get("start") or item.get("extra", {}).get("start") or {}
    end = item.get("end") or item.get("extra", {}).get("end") or {}
    extra = item.get("extra", {})
    return {
        "start": {"line": start.get("line", 1), "col": start.get("col", 0)},
        "end": {"line": end.get("line", start.get("line", 1)), "col": end.get("col", 0)},
        "extra": extra,
        "msg": item.get("msg") or extra.get("message") or item.get("message")
    }

# -------------------------
# Analyze Endpoint
# -------------------------
@app.post("/analyze")
async def analyze(req: AnalyzeReq) -> Dict[str, Any]:
    start_time = time.time()
    findings: Dict[str, Any] = {
        "semgrep": [], "bandit": [], "hf": None,
        "hf_findings": [], "gemini": None, "gemini_findings": []
    }

    # Cache check
    try:
        key = cache_key(req.code, req.filename, req.language)
        cached = CACHE.get(key)
        if cached and time.time() - cached["ts"] < 3600:
            res = cached["val"]
            res["cached"] = True
            res["timing_s"] = time.time() - start_time
            return res
    except Exception as e:
        logger.warning(f"Cache check failed: {e}")

    # Write temp file
    path = None
    try:
        with tempfile.NamedTemporaryFile(suffix="."+req.language, delete=False, mode="w", encoding="utf-8") as tf:
            path = tf.name
            tf.write(req.code)
    except Exception as e:
        findings["error"] = f"tempfile_error: {e}"
        findings["timing_s"] = time.time() - start_time
        return findings

    # -------------------------
    # Semgrep
    # -------------------------
    try:
        semgrep_cmd = ["semgrep", "--json", path]
        proc = subprocess.run(semgrep_cmd, capture_output=True, text=True, timeout=60)
        if proc.stdout:
            data = json.loads(proc.stdout)
            findings["semgrep"] = [_normalize_semgrep_item(i) for i in data.get("results", [])]
            logger.info(f"Semgrep found {len(findings['semgrep'])} issue(s)")
    except Exception as e:
        logger.warning(f"Semgrep failed: {e}")

    # -------------------------
    # Bandit (Python only)
    # -------------------------
    if req.language.lower() in ["py", "python"]:
        try:
            proc = subprocess.run(["bandit", "-f", "json", "-r", path], capture_output=True, text=True, timeout=10)
            if proc.stdout:
                bdata = json.loads(proc.stdout)
                findings["bandit"] = bdata.get("results", [])
                logger.info(f"Bandit found {len(findings['bandit'])} issue(s)")
        except Exception as e:
            logger.warning(f"Bandit failed: {e}")

    # -------------------------
    # Hugging Face
    # -------------------------
    try:
        if use_hf_inference_api and hf_inference_client:
            res = hf_inference_client.text_generation(HF_MODEL, req.code)
            findings["hf"] = res
        elif classifier:
            hf_result = classifier(req.code[:4096])
            findings["hf"] = hf_result
        logger.info("HF analysis complete")
    except Exception as e:
        logger.warning(f"HF scan failed: {e}")

    # HF synthetic findings
    try:
        if isinstance(findings.get("hf"), list) and findings["hf"]:
            top = findings["hf"][0]
            label = top.get("label", "")
            score = float(top.get("score", 0))
            if label.upper().startswith("LABEL_1") or score > 0.7:
                for idx, line in enumerate(req.code.splitlines()):
                    if line.strip():
                        findings["hf_findings"].append({
                            "message": f"HF flagged vulnerability (label={label}, score={score:.2f})",
                            "line": idx + 1,
                            "col": 0
                        })
                        break
    except Exception as e:
        logger.warning(f"HF findings parse failed: {e}")

    # -------------------------
    # Gemini Escalation
    # -------------------------
    try:
        escalate = bool(findings.get("semgrep") or findings.get("bandit") or findings.get("hf_findings"))
        # Force-enable Gemini temporarily for testing:
        # escalate = True
        logger.info(f"Gemini escalation: {escalate}, client: {bool(gemini_client)}")

        if escalate and gemini_client:
            prompt = (
                "Analyze the following code for vulnerabilities and respond in JSON:\n"
                "{ \"line\": <int>, \"type\": <string>, \"severity\": <low|medium|high>, \"explanation\": <string> }\n\n"
                f"Code:\n```\n{req.code}\n```"
            )

            logger.info("🔍 Sending code to Gemini...")
            try:
                # Use a stable model name
                resp = gemini_client.models.generate_content(
                    model="gemini-1.5-flash", contents=prompt
                )
                findings["gemini"] = resp.text
                logger.info(f"Gemini response: {resp.text[:200]}...")

                try:
                    gjson = json.loads(resp.text)
                    line = max(0, (gjson.get("line") or 1) - 1)
                    findings["gemini_findings"].append({
                        "message": f"{gjson.get('type', 'Vulnerability')} - {gjson.get('explanation', '')}",
                        "line": line,
                        "col": 0,
                        "severity": gjson.get("severity", "medium")
                    })
                except json.JSONDecodeError:
                    logger.warning("Gemini response was not valid JSON")

            except Exception as e:
                logger.warning(f"Gemini call failed: {e}")
    except Exception as e:
        logger.warning(f"Gemini block failed: {e}")

    # -------------------------
    # Timing & cache
    # -------------------------
    findings["timing_s"] = time.time() - start_time
    try:
        CACHE[key] = {"ts": time.time(), "val": findings}
    except Exception as e:
        logger.warning(f"Cache save failed: {e}")

    # -------------------------
    # Cleanup
    # -------------------------
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception as e:
        logger.warning(f"Cleanup failed: {e}")

    return findings
