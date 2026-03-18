"""
Re-identification Risk Scorer — calculates how easy it would be
to re-identify a person from a COMBINATION of data points,
even after partial redaction. Real-world GDPR thinking.
"""

from typing import List, Dict, Any

# How uniquely identifying is each field (0-1)
# Based on real anonymization research (Latanya Sweeney et al.)
UNIQUENESS_WEIGHTS = {
    "ssn":         1.00,  # Uniquely identifies 1 person
    "credit_card": 0.99,
    "email":       0.95,  # Almost always unique
    "api_key":     0.95,
    "phone":       0.90,
    "username":    0.75,
    "ip_address":  0.60,  # Shared IPs lower this
}

# Combinations that together create high re-id risk
# even if individually they seem low risk
DANGEROUS_COMBINATIONS = [
    ({"ip_address", "username"},    0.90, "IP + username combination is highly identifying"),
    ({"ip_address", "email"},       0.95, "IP + email allows cross-system identification"),
    ({"phone", "username"},         0.88, "Phone + username sufficient to identify individual"),
    ({"email", "ip_address", "phone"}, 0.99, "Triple combination: near-certain re-identification"),
]


def score_reidentification_risk(
    entity_types: List[str],
    redacted: List[str],
    pseudonymized: List[str],
) -> Dict[str, Any]:
    """
    Given what PII was found, what was redacted, and what was pseudonymized,
    calculate the residual re-identification risk of the OUTPUT text.
    """
    # Remaining exposed entities (not redacted, not pseudonymized)
    exposed = [
        e for e in entity_types
        if e not in redacted and e not in pseudonymized
    ]

    # Pseudonymized fields still carry some residual risk
    residual_pseudo = [e for e in pseudonymized]

    # Base risk from exposed fields
    base_risk = 0.0
    for entity in exposed:
        base_risk = max(base_risk, UNIQUENESS_WEIGHTS.get(entity, 0.4))

    # Combination risk — even pseudonymized combos can re-identify
    combo_risk = 0.0
    remaining = set(exposed + residual_pseudo)
    triggered_combos = []

    for combo, risk, reason in DANGEROUS_COMBINATIONS:
        if combo.issubset(remaining):
            combo_risk = max(combo_risk, risk * 0.6)  # Discounted for pseudonymization
            triggered_combos.append(reason)

    final_risk = min(round(max(base_risk, combo_risk), 3), 1.0)

    risk_level = (
        "critical" if final_risk >= 0.85 else
        "high"     if final_risk >= 0.65 else
        "medium"   if final_risk >= 0.35 else
        "low"
    )

    return {
        "reidentification_risk_score": final_risk,
        "risk_level": risk_level,
        "exposed_fields": exposed,
        "pseudonymized_fields": residual_pseudo,
        "redacted_fields": redacted,
        "dangerous_combinations_found": triggered_combos,
        "recommendation": {
            "critical": "Re-identification still highly likely. Redact all remaining fields.",
            "high":     "Significant re-identification risk remains. Consider redacting pseudonymized fields.",
            "medium":   "Moderate risk. Review combination of retained fields.",
            "low":      "Low re-identification risk. Current sanitization is adequate.",
        }.get(risk_level, "Review sanitization strategy."),
    }
