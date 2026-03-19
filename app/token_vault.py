"""
Token Vault — secure bidirectional PII mapping.
Converts PII to tokens before LLM, restores original values in response.

Flow:
  User input: "Email Harry at harry@corp.com"
  → Vault stores: {USER_A: "Harry", EMAIL_A: "harry@corp.com"}
  → To LLM: "Email [USER_A] at [EMAIL_A]"
  → LLM reply: "I will email [USER_A] at [EMAIL_A] now."
  → To user: "I will email Harry at harry@corp.com now."
"""
import hashlib
import threading
from typing import Dict, Optional
from datetime import datetime, timedelta

class TokenVault:
    def __init__(self, ttl_minutes: int = 60):
        self._lock = threading.Lock()
        self._vault: Dict[str, Dict] = {}  # scope_id -> {token -> original}
        self._counters: Dict[str, Dict] = {}  # scope_id -> {entity_type -> count}
        self.ttl = timedelta(minutes=ttl_minutes)

    def store(self, scope_id: str, value: str, entity_type: str) -> str:
        """Store a PII value and return a readable token like [USER_A]."""
        with self._lock:
            if scope_id not in self._vault:
                self._vault[scope_id] = {}
                self._counters[scope_id] = {}

            # Check if already stored
            for token, entry in self._vault[scope_id].items():
                if entry["value"] == value:
                    return token

            # Generate readable token
            prefix = self._get_prefix(entity_type)
            count = self._counters[scope_id].get(entity_type, 0)
            letter = chr(65 + (count % 26))  # A, B, C...
            token = f"[{prefix}_{letter}]"
            self._counters[scope_id][entity_type] = count + 1

            self._vault[scope_id][token] = {
                "value": value,
                "entity_type": entity_type,
                "created": datetime.utcnow(),
            }
            return token

    def restore(self, scope_id: str, text: str) -> str:
        """Replace all tokens in text with their original PII values."""
        with self._lock:
            if scope_id not in self._vault:
                return text
            result = text
            for token, entry in self._vault[scope_id].items():
                result = result.replace(token, entry["value"])
            return result

    def get_mappings(self, scope_id: str) -> Dict:
        """Return all token→value mappings for a scope."""
        with self._lock:
            return {
                token: entry["value"]
                for token, entry in self._vault.get(scope_id, {}).items()
            }

    def clear_scope(self, scope_id: str):
        """Clear all mappings for a scope after session ends."""
        with self._lock:
            self._vault.pop(scope_id, None)
            self._counters.pop(scope_id, None)

    def _get_prefix(self, entity_type: str) -> str:
        return {
            "email": "EMAIL",
            "phone": "PHONE",
            "ip_address": "IP",
            "ssn": "SSN",
            "credit_card": "CARD",
            "api_key": "KEY",
            "username": "USER",
            "person_name": "USER",
            "location": "PLACE",
        }.get(entity_type, "PII")


# Global vault instance
vault = TokenVault()
