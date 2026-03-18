import time
import logging
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app.detector import detect_pii
from app.policy_engine import PolicyEngine
from app.sanitizer import sanitize

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pii-safe")

class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1)

class ScanResponse(BaseModel):
    entity_types_found: List[str]
    total_matches: int
    risk_score: float
    matches: List[Dict[str, Any]]

class SanitizeRequest(BaseModel):
    text: str = Field(..., min_length=1)
    operation: str = "analysis"
    scope_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class SanitizeResponse(BaseModel):
    sanitized_text: str
    original_text: str
    decision: str
    matched_rule: str
    risk_score: float
    scope_id: str
    total_pii_found: int
    entities_summary: Dict[str, int]
    transformations: List[Dict[str, Any]]

class BatchRequest(BaseModel):
    texts: List[str]
    operation: str = "analysis"
    scope_id: Optional[str] = None

policy_engine: PolicyEngine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global policy_engine
    logger.info("Loading PII-Safe policy engine...")
    policy_engine = PolicyEngine("policies/default.yaml")
    logger.info(f"Loaded {len(policy_engine.policies)} policy rules.")
    yield

app = FastAPI(title="PII-Safe", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration}ms)")
    return response

@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0", "rules_loaded": len(policy_engine.policies)}

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    result = detect_pii(req.text)
    return ScanResponse(
        entity_types_found=result.entity_types_found,
        total_matches=len(result.matches),
        risk_score=result.risk_score,
        matches=[{"entity_type": m.entity_type, "value": m.value, "start": m.start, "end": m.end, "confidence": m.confidence} for m in result.matches],
    )

@app.post("/sanitize", response_model=SanitizeResponse)
def sanitize_text(req: SanitizeRequest):
    detection = detect_pii(req.text)
    if not detection.matches:
        return SanitizeResponse(
            sanitized_text=req.text, original_text=req.text,
            decision="allow", matched_rule="no_pii_detected",
            risk_score=0.0, scope_id=req.scope_id or "none",
            total_pii_found=0, entities_summary={}, transformations=[],
        )
    policy_decision = policy_engine.evaluate(req.operation, detection.entity_types_found, req.context)
    report = sanitize(req.text, detection.matches, policy_decision.decision, detection.risk_score,
                      policy_decision.matched_rule, policy_decision.affected_entities, req.scope_id)
    return SanitizeResponse(
        sanitized_text=report.sanitized_text, original_text=report.original_text,
        decision=report.decision, matched_rule=report.matched_rule,
        risk_score=report.risk_score, scope_id=report.scope_id,
        total_pii_found=report.total_pii_found, entities_summary=report.entities_summary,
        transformations=[{"entity_type": t.entity_type, "original": t.original, "replacement": t.replacement, "action": t.action} for t in report.transformations],
    )

@app.post("/batch")
def batch_sanitize(req: BatchRequest):
    start = time.time()
    results = [sanitize_text(SanitizeRequest(text=t, operation=req.operation, scope_id=req.scope_id)) for t in req.texts]
    return {"results": results, "total_processed": len(results), "processing_time_ms": round((time.time() - start) * 1000, 2)}

@app.get("/policies")
def list_policies():
    return {"total_rules": len(policy_engine.policies), "rules": policy_engine.policies}

@app.post("/policies/reload")
def reload_policies():
    try:
        policy_engine.reload()
        return {"status": "reloaded", "rules_loaded": len(policy_engine.policies)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── New Unique Feature Endpoints ────────────────────────────────────────────

from app.compliance import map_compliance
from app.injection_shield import scan_for_injection
from app.reidentification import score_reidentification_risk

class FullAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1)
    operation: str = "analysis"
    scope_id: Optional[str] = None

@app.post("/analyze")
def full_analysis(req: FullAnalysisRequest):
    """
    Full pipeline: PII detection + sanitization + compliance mapping
    + injection shield + re-identification risk score.
    All in one call.
    """
    # Step 1: Check for prompt injection first
    injection = scan_for_injection(req.text)

    # Step 2: Detect PII
    detection = detect_pii(req.text)

    # Step 3: Apply policy
    policy_decision = policy_engine.evaluate(
        req.operation,
        detection.entity_types_found,
        {}
    ) if detection.matches else None

    # Step 4: Sanitize
    report = None
    if detection.matches and policy_decision:
        report = sanitize(
            req.text,
            detection.matches,
            policy_decision.decision,
            detection.risk_score,
            policy_decision.matched_rule,
            policy_decision.affected_entities,
            req.scope_id,
        )

    # Step 5: Compliance mapping
    compliance = map_compliance(detection.entity_types_found)

    # Step 6: Re-identification risk
    redacted = [t.entity_type for t in report.transformations if t.action == "redacted"] if report else []
    pseudonymized = [t.entity_type for t in report.transformations if t.action == "pseudonymized"] if report else []
    reid_risk = score_reidentification_risk(
        detection.entity_types_found,
        redacted,
        pseudonymized,
    )

    return {
        "sanitized_text": report.sanitized_text if report else req.text,
        "decision": policy_decision.decision if policy_decision else "allow",
        "pii_detection": {
            "entity_types_found": detection.entity_types_found,
            "total_matches": len(detection.matches),
            "risk_score": detection.risk_score,
        },
        "injection_shield": injection,
        "compliance": compliance,
        "reidentification_risk": reid_risk,
    }

@app.post("/injection-scan")
def injection_scan(req: ScanRequest):
    """Scan text specifically for prompt injection attacks."""
    return scan_for_injection(req.text)

@app.post("/compliance-check")
def compliance_check(req: ScanRequest):
    """Detect PII and return full compliance violation report."""
    detection = detect_pii(req.text)
    return map_compliance(detection.entity_types_found)


from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

@app.get("/")
def serve_demo():
    return FileResponse("demo.html")
