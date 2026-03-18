import uuid
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from app.detector import PIIMatch, pseudonymize

@dataclass
class Transformation:
    entity_type: str
    original: str
    replacement: str
    action: str
    start: int
    end: int

@dataclass
class SanitizationReport:
    original_text: str
    sanitized_text: str
    transformations: List[Transformation]
    risk_score: float
    decision: str
    matched_rule: str
    scope_id: str
    total_pii_found: int
    entities_summary: Dict[str, int] = field(default_factory=dict)

def sanitize(text, matches, decision, risk_score, matched_rule, affected_entities, scope_id=None):
    scope_id = scope_id or str(uuid.uuid4())
    transformations = []

    if decision == "block":
        return SanitizationReport(
            original_text=text,
            sanitized_text="[BLOCKED: Policy denied this operation]",
            transformations=[],
            risk_score=risk_score,
            decision=decision,
            matched_rule=matched_rule,
            scope_id=scope_id,
            total_pii_found=len(matches),
            entities_summary=_summarize(matches),
        )

    if decision == "allow":
        return SanitizationReport(
            original_text=text,
            sanitized_text=text,
            transformations=[],
            risk_score=risk_score,
            decision=decision,
            matched_rule=matched_rule,
            scope_id=scope_id,
            total_pii_found=len(matches),
            entities_summary=_summarize(matches),
        )

    sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
    sanitized = text

    for match in sorted_matches:
        if match.entity_type not in affected_entities:
            continue
        if decision == "redact":
            replacement = f"[{match.entity_type.upper()}_REDACTED]"
            action = "redacted"
        elif decision == "pseudonymize":
            replacement = pseudonymize(match.value, match.entity_type, scope_id)
            action = "pseudonymized"
        else:
            continue
        transformations.append(Transformation(
            entity_type=match.entity_type,
            original=match.value,
            replacement=replacement,
            action=action,
            start=match.start,
            end=match.end,
        ))
        sanitized = sanitized[:match.start] + replacement + sanitized[match.end:]

    return SanitizationReport(
        original_text=text,
        sanitized_text=sanitized,
        transformations=transformations,
        risk_score=risk_score,
        decision=decision,
        matched_rule=matched_rule,
        scope_id=scope_id,
        total_pii_found=len(matches),
        entities_summary=_summarize(matches),
    )

def _summarize(matches):
    summary = {}
    for m in matches:
        summary[m.entity_type] = summary.get(m.entity_type, 0) + 1
    return summary
