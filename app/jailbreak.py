import re
from typing import Dict, Any

PATTERNS = [
    (r"(show|print|output|list|dump)\s+(all\s+)?(user|customer|patient)\s+(data|records|pii|emails|phones)", "pii_extraction", "critical", "Attempting to extract bulk PII"),
    (r"(ignore|forget|override|bypass)\s+(all\s+)?(previous|prior|system)\s+(instructions|prompt|rules)", "instruction_override", "critical", "Attempting to override system instructions"),
    (r"(what|tell me|show me|list).{0,30}(other users?|other customers?)", "cross_user_leak", "critical", "Attempting to access other users data"),
    (r"(training data|your database|stored data).{0,20}(show|reveal|output|print)", "training_extraction", "critical", "Attempting to extract database"),
    (r"(developer|debug|admin|root|sudo)\s+(mode|access|override)", "privilege_escalation", "high", "Attempting privilege escalation"),
    (r"(grandma|roleplay|hypothetically|fictional).{0,50}(password|ssn|credit card|private|secret)", "social_engineering", "high", "Social engineering attempt"),
    (r"(what|list|show).{0,20}(emails?|phone numbers?|ssn).{0,20}(stored|database|users?)", "data_enumeration", "critical", "Attempting to enumerate stored PII"),
]

SS = {"critical": 1.0, "high": 0.75, "medium": 0.5}

def scan_jailbreak(text: str) -> Dict[str, Any]:
    findings = []
    for pattern, name, severity, description in PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append({"pattern_name": name, "severity": severity, "matched_text": m.group(0)[:100], "description": description, "position": m.start()})
    if not findings:
        return {"jailbreak_detected": False, "findings": [], "highest_severity": None, "jailbreak_score": 0.0, "recommendation": "No jailbreak patterns detected.", "action": "allow"}
    highest = max(findings, key=lambda f: SS.get(f["severity"], 0))
    score = SS.get(highest["severity"], 0.0)
    recs = {"critical": "BLOCK IMMEDIATELY: Critical jailbreak attempt detected.", "high": "BLOCK: High-risk attack pattern detected."}
    return {"jailbreak_detected": True, "findings": findings, "highest_severity": highest["severity"], "jailbreak_score": score, "recommendation": recs.get(highest["severity"], "Review required."), "action": "BLOCK", "total_patterns": len(findings)}
