import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

VALID_DECISIONS = {"allow", "redact", "pseudonymize", "block"}

@dataclass
class PolicyDecision:
    decision: str
    matched_rule: str
    affected_entities: List[str]
    reason: str

class PolicyEngine:
    def __init__(self, policy_path: str = "policies/default.yaml"):
        self.policy_path = Path(policy_path)
        self.policies: List[Dict[str, Any]] = []
        self._load()

    def _load(self):
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")
        with open(self.policy_path) as f:
            data = yaml.safe_load(f)
        self.policies = data.get("rules", [])

    def reload(self):
        self._load()

    def evaluate(self, operation: str, entity_types: List[str], context: Optional[Dict[str, Any]] = None) -> PolicyDecision:
        for rule in self.policies:
            if not self._matches_rule(rule, operation, entity_types, context or {}):
                continue
            decision = rule.get("decision", "block")
            if decision not in VALID_DECISIONS:
                raise ValueError(f"Invalid decision '{decision}'")
            affected = [et for et in entity_types if et in rule.get("entities", entity_types)]
            return PolicyDecision(
                decision=decision,
                matched_rule=rule.get("name", "unnamed"),
                affected_entities=affected or entity_types,
                reason=rule.get("reason", f"Matched rule: {rule.get('name', 'unnamed')}"),
            )
        return PolicyDecision(
            decision="block",
            matched_rule="__default_deny__",
            affected_entities=entity_types,
            reason="No matching policy rule found. Default deny applied.",
        )

    def _matches_rule(self, rule: Dict[str, Any], operation: str, entity_types: List[str], context: Dict[str, Any]) -> bool:
        rule_ops = rule.get("operations", [])
        if rule_ops and operation not in rule_ops:
            return False
        rule_entities = rule.get("entities", [])
        if rule_entities:
            if not any(et in rule_entities for et in entity_types):
                return False
        for key, expected in rule.get("conditions", {}).items():
            if context.get(key) != expected:
                return False
        return True
