"""
Compliance Mapper — maps detected PII to real privacy regulations.
Tells you WHICH law you are violating and WHAT action is required.
Covers: GDPR, HIPAA, CCPA
"""

from typing import List, Dict, Any

COMPLIANCE_MAP = {
    "email": [
        {"law": "GDPR", "article": "Article 17", "requirement": "Right to erasure applies. Must be redacted or deleted on request.", "severity": "high"},
        {"law": "CCPA", "article": "Section 1798.105", "requirement": "Consumer has right to deletion of personal information.", "severity": "high"},
    ],
    "ip_address": [
        {"law": "GDPR", "article": "Recital 30", "requirement": "IP addresses are personal data. Requires lawful basis for processing.", "severity": "medium"},
        {"law": "CCPA", "article": "Section 1798.140", "requirement": "IP address qualifies as personal information under CCPA.", "severity": "medium"},
    ],
    "ssn": [
        {"law": "HIPAA", "article": "45 CFR 164.514(b)", "requirement": "SSN is an explicit identifier. Must be removed for Safe Harbor de-identification.", "severity": "critical"},
        {"law": "GDPR", "article": "Article 9", "requirement": "Qualifies as sensitive data. Explicit consent or legal basis required.", "severity": "critical"},
    ],
    "credit_card": [
        {"law": "PCI-DSS", "article": "Requirement 3", "requirement": "Primary Account Number must be masked or encrypted at rest.", "severity": "critical"},
        {"law": "GDPR", "article": "Article 32", "requirement": "Financial data requires appropriate technical security measures.", "severity": "critical"},
    ],
    "phone": [
        {"law": "GDPR", "article": "Article 17", "requirement": "Phone numbers are personal data subject to erasure rights.", "severity": "high"},
        {"law": "CCPA", "article": "Section 1798.140", "requirement": "Phone number is personal information under CCPA.", "severity": "high"},
        {"law": "HIPAA", "article": "45 CFR 164.514(b)", "requirement": "Phone numbers must be removed for Safe Harbor de-identification.", "severity": "high"},
    ],
    "api_key": [
        {"law": "GDPR", "article": "Article 32", "requirement": "Authentication credentials require strict access controls and encryption.", "severity": "critical"},
        {"law": "SOC2", "article": "CC6.1", "requirement": "Logical access controls must protect credentials from unauthorized access.", "severity": "critical"},
    ],
    "username": [
        {"law": "GDPR", "article": "Article 4", "requirement": "Usernames can identify individuals and qualify as personal data.", "severity": "medium"},
        {"law": "CCPA", "article": "Section 1798.140", "requirement": "Account identifiers are personal information under CCPA.", "severity": "medium"},
    ],
}

SEVERITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


def map_compliance(entity_types: List[str]) -> Dict[str, Any]:
    """
    Given a list of detected PII entity types, return:
    - All applicable regulations
    - Highest severity level
    - Recommended action
    - Compliance risk score
    """
    violations = []
    seen = set()
    max_severity = "low"

    for entity_type in entity_types:
        rules = COMPLIANCE_MAP.get(entity_type, [])
        for rule in rules:
            key = f"{entity_type}:{rule['law']}:{rule['article']}"
            if key in seen:
                continue
            seen.add(key)
            violations.append({
                "entity_type": entity_type,
                "law": rule["law"],
                "article": rule["article"],
                "requirement": rule["requirement"],
                "severity": rule["severity"],
            })
            if SEVERITY_SCORE.get(rule["severity"], 0) > SEVERITY_SCORE.get(max_severity, 0):
                max_severity = rule["severity"]

    laws_triggered = list({v["law"] for v in violations})
    compliance_score = SEVERITY_SCORE.get(max_severity, 0.0)

    recommendation = {
        "critical": "IMMEDIATE ACTION REQUIRED: Redact all identified fields before any processing or storage.",
        "high":     "Redact or pseudonymize identified fields. Ensure lawful basis for processing is documented.",
        "medium":   "Review data minimization policies. Consider pseudonymization for identified fields.",
        "low":      "Monitor and document processing activities for identified fields.",
    }.get(max_severity, "Review data handling policies.")

    return {
        "violations": violations,
        "laws_triggered": laws_triggered,
        "highest_severity": max_severity,
        "compliance_risk_score": compliance_score,
        "recommendation": recommendation,
        "total_violations": len(violations),
    }
