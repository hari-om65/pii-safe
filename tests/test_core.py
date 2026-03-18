import sys
sys.path.insert(0, '.')
import pytest
from app.detector import detect_pii, pseudonymize
from app.policy_engine import PolicyEngine
from app.sanitizer import sanitize

class TestDetector:
    def test_detects_email(self):
        result = detect_pii("Contact john.doe@example.com for support.")
        assert "email" in result.entity_types_found

    def test_detects_ip_address(self):
        result = detect_pii("Request from 192.168.1.100 was blocked.")
        assert "ip_address" in result.entity_types_found

    def test_detects_phone(self):
        result = detect_pii("Call us at 415-555-0123 anytime.")
        assert "phone" in result.entity_types_found

    def test_detects_ssn(self):
        result = detect_pii("SSN on file: 123-45-6789")
        assert "ssn" in result.entity_types_found

    def test_detects_credit_card(self):
        result = detect_pii("Charged card 4111111111111111 successfully.")
        assert "credit_card" in result.entity_types_found

    def test_no_false_positives(self):
        result = detect_pii("The server processed 42 requests in 3 seconds.")
        assert len(result.matches) == 0
        assert result.risk_score == 0.0

    def test_risk_score_increases_with_more_pii(self):
        single = detect_pii("Email: user@test.com")
        multi  = detect_pii("Email: user@test.com, SSN: 123-45-6789, IP: 10.0.0.1")
        assert multi.risk_score > single.risk_score

class TestPseudonymize:
    def test_same_value_same_scope_same_token(self):
        t1 = pseudonymize("alice@test.com", "email", "incident-001")
        t2 = pseudonymize("alice@test.com", "email", "incident-001")
        assert t1 == t2

    def test_different_scope_different_token(self):
        t1 = pseudonymize("alice@test.com", "email", "incident-001")
        t2 = pseudonymize("alice@test.com", "email", "incident-002")
        assert t1 != t2

    def test_token_has_correct_prefix(self):
        token = pseudonymize("192.168.1.1", "ip_address", "scope-y")
        assert token.startswith("IPADDRESS_")

class TestPolicyEngine:
    @pytest.fixture
    def engine(self):
        return PolicyEngine("policies/default.yaml")

    def test_analysis_pseudonymizes_email(self, engine):
        decision = engine.evaluate("analysis", ["email"])
        assert decision.decision == "pseudonymize"

    def test_export_redacts_all(self, engine):
        decision = engine.evaluate("export", ["email", "ip_address"])
        assert decision.decision == "redact"

    def test_analysis_redacts_ssn(self, engine):
        decision = engine.evaluate("analysis", ["ssn"])
        assert decision.decision == "redact"

    def test_unknown_operation_blocks(self, engine):
        decision = engine.evaluate("unknown_op", ["email"])
        assert decision.decision == "block"

class TestSanitizer:
    def test_redaction_replaces_pii(self):
        text = "Contact user@test.com please"
        from app.detector import detect_pii as _detect
        matches = _detect(text).matches
        report = sanitize(text, matches, "redact", 0.7, "rule", ["email"], "scope-1")
        assert "user@test.com" not in report.sanitized_text
        assert "[EMAIL_REDACTED]" in report.sanitized_text

    def test_pseudonymization_consistent(self):
        text = "Contact user@test.com please"
        from app.detector import detect_pii as _detect
        matches = _detect(text).matches
        r1 = sanitize(text, matches, "pseudonymize", 0.7, "rule", ["email"], "scope-abc")
        r2 = sanitize(text, matches, "pseudonymize", 0.7, "rule", ["email"], "scope-abc")
        assert r1.sanitized_text == r2.sanitized_text

    def test_block_returns_blocked_message(self):
        from app.detector import detect_pii as _detect
        text = "SSN: 123-45-6789"
        matches = _detect(text).matches
        report = sanitize(text, matches, "block", 1.0, "rule", ["ssn"])
        assert "BLOCKED" in report.sanitized_text

    def test_allow_returns_original(self):
        from app.detector import detect_pii as _detect
        text = "IP: 10.0.0.1"
        matches = _detect(text).matches
        report = sanitize(text, matches, "allow", 0.5, "rule", ["ip_address"])
        assert report.sanitized_text == text
