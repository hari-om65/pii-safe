"""
Prompt Injection Shield — detects malicious LLM instructions
hidden inside PII data fields before they reach the model.
This is critical for agentic AI safety.
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass

INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override", "critical"),
    (r"forget\s+(everything|all|prior|previous)", "memory_wipe", "critical"),
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+AI)", "persona_hijack", "critical"),
    (r"act\s+as\s+(if\s+you\s+are\s+)?(?!an?\s+AI)", "persona_hijack", "critical"),
    (r"do\s+not\s+(follow|obey|apply)\s+(your\s+)?(rules|guidelines|policy|policies)", "policy_bypass", "critical"),
    (r"(reveal|show|print|output|display)\s+(your\s+)?(system\s+prompt|instructions|prompt)", "prompt_leak", "high"),
    (r"(disable|bypass|skip|override)\s+(safety|filter|restriction|guard|policy)", "safety_bypass", "high"),
    (r"translate\s+.*\s+to\s+\w+\s+and\s+then\s+(execute|run|do)", "encoded_injection", "high"),
    (r"<\s*script[^>]*>", "script_injection", "high"),
    (r"(sudo|admin|root|superuser)\s+(mode|access|privilege)", "privilege_escalation", "medium"),
    (r"repeat\s+(after\s+me|the\s+following|this)", "repetition_attack", "medium"),
    (r"(system|assistant|human)\s*:\s*\n", "role_spoofing", "medium"),
    (r"\\n\\n(human|user|system)\s*:", "delimiter_injection", "medium"),
    (r"base64\s*:\s*[A-Za-z0-9+/=]{20,}", "encoded_payload", "high"),
]

SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


@dataclass
class InjectionMatch:
    pattern_name: str
    severity: str
    matched_text: str
    position: int


def scan_for_injection(text: str) -> Dict[str, Any]:
    """
    Scan text for prompt injection attempts.
    Returns detection results with severity and recommended action.
    """
    findings: List[InjectionMatch] = []

    for pattern, name, severity in INJECTION_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(InjectionMatch(
                pattern_name=name,
                severity=severity,
                matched_text=match.group(0),
                position=match.start(),
            ))

    if not findings:
        return {
            "injection_detected": False,
            "findings": [],
            "highest_severity": None,
            "injection_risk_score": 0.0,
            "recommendation": "No injection patterns detected. Safe to process.",
        }

    highest = max(findings, key=lambda f: SEVERITY_SCORE.get(f.severity, 0))

    return {
        "injection_detected": True,
        "findings": [
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity,
                "matched_text": f.matched_text,
                "position": f.position,
            }
            for f in findings
        ],
        "highest_severity": highest.severity,
        "injection_risk_score": SEVERITY_SCORE.get(highest.severity, 0.0),
        "recommendation": {
            "critical": "BLOCK IMMEDIATELY: Critical injection attempt detected. Do not process this input.",
            "high":     "BLOCK: High-risk injection pattern found. Sanitize or reject this input.",
            "medium":   "WARN: Suspicious patterns detected. Review before processing.",
        }.get(highest.severity, "Review input before processing."),
        "total_patterns_found": len(findings),
    }
