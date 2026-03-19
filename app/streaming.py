"""
Streaming PII Redaction — scans LLM token streams in real time.
Supports Server-Sent Events (SSE) and WebSocket streams.

Uses a sliding window buffer to catch PII that spans multiple tokens:
  Token 1: "john"
  Token 2: ".doe"
  Token 3: "@gmail"   ← flush buffer, redact email
  Token 4: ".com"
"""
import re
from typing import Generator, List, Callable
from app.detector import PATTERNS

BUFFER_SIZE = 50  # characters to buffer before flushing


class StreamingRedactor:
    def __init__(self, scope_id: str, decision: str = "redact"):
        self.scope_id = scope_id
        self.decision = decision
        self.buffer = ""

    def process_token(self, token: str) -> str:
        """
        Process a single streaming token.
        Returns safe text to pass through immediately.
        """
        self.buffer += token
        output = ""

        # Only flush when buffer is large enough or contains safe prefix
        if len(self.buffer) >= BUFFER_SIZE:
            output = self._scan_and_flush()

        return output

    def flush(self) -> str:
        """Flush remaining buffer at end of stream."""
        return self._scan_and_flush(force=True)

    def _scan_and_flush(self, force: bool = False) -> str:
        """Scan buffer for PII and flush safe portion."""
        text = self.buffer
        # Scan for all PII patterns
        matches = []
        for entity_type, (pattern, conf) in PATTERNS.items():
            for m in re.finditer(pattern, text, re.IGNORECASE):
                matches.append((m.start(), m.end(), entity_type, m.group(0)))

        if not matches:
            if force:
                self.buffer = ""
                return text
            # Keep last 20 chars in buffer (might be partial PII)
            safe = text[:-20] if len(text) > 20 else ""
            self.buffer = text[-20:] if len(text) > 20 else text
            return safe

        # Sort matches and apply redaction
        matches.sort(key=lambda x: x[0], reverse=True)
        result = text
        for start, end, etype, value in matches:
            if self.decision == "redact":
                rep = f"[{etype.upper().replace('_','')}_REDACTED]"
            else:
                rep = f"[{etype.upper().replace('_','')}_A]"
            result = result[:start] + rep + result[end:]

        self.buffer = ""
        return result


def redact_stream(
    token_generator: Generator,
    scope_id: str,
    decision: str = "redact"
) -> Generator:
    """
    Wrap any token generator with streaming PII redaction.
    
    Usage:
        safe_stream = redact_stream(llm.stream(prompt), scope_id="session-1")
        for token in safe_stream:
            send_to_client(token)
    """
    redactor = StreamingRedactor(scope_id, decision)
    for token in token_generator:
        safe = redactor.process_token(token)
        if safe:
            yield safe
    # Flush remaining buffer
    remaining = redactor.flush()
    if remaining:
        yield remaining
