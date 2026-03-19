"""
Synthetic Data Injection — replaces PII with realistic fake data.
LLMs perform better with natural text than [REDACTED] brackets.

Example:
  "Email john.doe@gmail.com" → "Email alex.smith@example.com"
  "Call 415-555-0199"        → "Call 800-555-0100"
  "IP: 192.168.1.45"         → "IP: 203.0.113.1"
"""
import hashlib
from typing import Optional

# Pools of synthetic values — deterministic based on hash
FAKE_FIRST = ["Alex","Jordan","Morgan","Taylor","Casey","Riley","Avery","Quinn"]
FAKE_LAST  = ["Smith","Johnson","Williams","Brown","Jones","Davis","Miller","Wilson"]
FAKE_DOMAINS = ["example.com","test.org","sample.net","demo.io","placeholder.dev"]
FAKE_COMPANIES = ["Acme Corp","Globex","Initech","Umbrella Ltd","Cyberdyne Systems"]

def _idx(value: str, pool_size: int) -> int:
    """Deterministic index from value hash."""
    return int(hashlib.md5(value.encode()).hexdigest(), 16) % pool_size

def synthetic_email(original: str) -> str:
    i = _idx(original, len(FAKE_FIRST))
    j = _idx(original + "last", len(FAKE_LAST))
    k = _idx(original + "domain", len(FAKE_DOMAINS))
    first = FAKE_FIRST[i].lower()
    last = FAKE_LAST[j].lower()
    domain = FAKE_DOMAINS[k]
    return f"{first}.{last}@{domain}"

def synthetic_phone(original: str) -> str:
    # Always use 800-555-XXXX format (safe fictional range)
    i = _idx(original, 9000)
    suffix = str(1000 + i).zfill(4)
    return f"800-555-{suffix}"

def synthetic_ip(original: str) -> str:
    # Use TEST-NET range (RFC 5737) — 203.0.113.x
    i = _idx(original, 254)
    return f"203.0.113.{i + 1}"

def synthetic_name(original: str) -> str:
    i = _idx(original, len(FAKE_FIRST))
    j = _idx(original + "last", len(FAKE_LAST))
    return f"{FAKE_FIRST[i]} {FAKE_LAST[j]}"

def synthetic_ssn(original: str) -> str:
    return "000-00-0000"

def synthetic_card(original: str) -> str:
    return "4000-0000-0000-0000"

def get_synthetic(value: str, entity_type: str) -> Optional[str]:
    """Return realistic synthetic replacement for any PII type."""
    handlers = {
        "email":       synthetic_email,
        "phone":       synthetic_phone,
        "ip_address":  synthetic_ip,
        "person_name": synthetic_name,
        "ssn":         synthetic_ssn,
        "credit_card": synthetic_card,
    }
    fn = handlers.get(entity_type)
    return fn(value) if fn else None
