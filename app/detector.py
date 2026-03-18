import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

@dataclass
class PIIMatch:
    entity_type: str
    value: str
    start: int
    end: int
    confidence: float

@dataclass
class DetectionResult:
    original_text: str
    matches: List[PIIMatch] = field(default_factory=list)
    entity_types_found: List[str] = field(default_factory=list)
    risk_score: float = 0.0

PATTERNS: Dict[str, Tuple[str, float]] = {
    "email": (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.95),
    "ip_address": (r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", 0.90),
    "phone": (r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b", 0.80),
    "credit_card": (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", 0.97),
    "ssn": (r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0.98),
    "api_key": (r"\b(?:sk|pk|api|key|token)[_\-][a-zA-Z0-9_\-]{8,}\b", 0.75),
    "username": (r"(?:user(?:name)?|login|account)\s*[=:]\s*['\"]?([A-Za-z0-9_.\-@]{3,30})['\"]?", 0.70),
}

RISK_WEIGHTS: Dict[str, float] = {
    "ssn": 1.0, "credit_card": 1.0, "api_key": 0.9,
    "email": 0.7, "phone": 0.7, "ip_address": 0.5, "username": 0.4,
}

def detect_pii(text: str) -> DetectionResult:
    result = DetectionResult(original_text=text)
    seen_spans: List[Tuple[int, int]] = []
    for entity_type, (pattern, confidence) in PATTERNS.items():
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start, end = match.start(), match.end()
            if any(s <= start < e or s < end <= e for s, e in seen_spans):
                continue
            value = match.group(0)
            result.matches.append(PIIMatch(entity_type, value, start, end, confidence))
            seen_spans.append((start, end))
            if entity_type not in result.entity_types_found:
                result.entity_types_found.append(entity_type)
    result.risk_score = _calculate_risk_score(result.matches)
    return result

def _calculate_risk_score(matches: List[PIIMatch]) -> float:
    if not matches:
        return 0.0
    entity_types = {m.entity_type for m in matches}
    score = sum(RISK_WEIGHTS.get(et, 0.5) for et in entity_types)
    count_factor = min(len(matches) / 10, 1.0) * 0.2
    return min(round(score / len(RISK_WEIGHTS) + count_factor, 3), 1.0)

def pseudonymize(value: str, entity_type: str, scope_id: str) -> str:
    digest = hashlib.sha256(f"{scope_id}:{entity_type}:{value}".encode()).hexdigest()[:8]
    prefix = entity_type.upper().replace("_", "")
    return f"{prefix}_{digest}"
