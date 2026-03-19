"""
NER Detector - upgrades regex with spaCy Named Entity Recognition.
Catches names, addresses, organizations that regex cannot detect.
"""
from app.detector import detect_pii, PIIMatch

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False

FORMAT_PRESERVING = {
    "phone": "999-000-0000",
    "credit_card": "4000000000000000",
    "ssn": "000-00-0000",
    "ip_address": "0.0.0.0",
    "email": "redacted@redacted.com",
}

SPACY_MAP = {
    "PERSON": "person_name",
    "GPE": "location",
    "LOC": "location",
    "FAC": "address",
}

def detect_pii_enhanced(text: str):
    result = detect_pii(text)
    if not SPACY_AVAILABLE:
        return result
    doc = nlp(text)
    seen = [(m.start, m.end) for m in result.matches]
    for ent in doc.ents:
        etype = SPACY_MAP.get(ent.label_)
        if not etype:
            continue
        s, e = ent.start_char, ent.end_char
        if any(ss <= s and e <= se for ss, se in seen):
            continue
        if len(ent.text.strip()) < 3:
            continue
        result.matches.append(PIIMatch(etype, ent.text, s, e, 0.80))
        seen.append((s, e))
        if etype not in result.entity_types_found:
            result.entity_types_found.append(etype)
    return result

def format_preserving_replacement(value: str, entity_type: str):
    return FORMAT_PRESERVING.get(entity_type, None)
