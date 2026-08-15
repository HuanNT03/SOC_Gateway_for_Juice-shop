"""
Unit Tests for Streamlit UI Helper Functions (Plan 5)

File: tests/test_ui.py
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agent.ui import load_audit_logs, get_status_badge_html


class TestStreamlitUI(unittest.TestCase):
    """Bộ kiểm thử cho Streamlit UI helpers."""

    def test_get_status_badge_html(self):
        """Kiểm thử HTML badge trả về theo từng status code."""
        badge_200 = get_status_badge_html(200)
        self.assertIn("200 ok", badge_200.lower())

        badge_413 = get_status_badge_html(413)
        self.assertIn("413", badge_413)
        self.assertIn("payload too large", badge_413.lower())

        badge_429 = get_status_badge_html(429)
        self.assertIn("429", badge_429)
        self.assertIn("rate limit", badge_429.lower())

    def test_load_audit_logs(self):
        """Kiểm thử đọc và nạp tệp log JSONL."""
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".jsonl") as tf:
            tf.write(json.dumps({
                "timestamp": "2026-08-15T10:00:00Z",
                "endpoint": "/api/Quantitys",
                "method": "GET",
                "status_code": 200,
                "request_headers": {"x-api-key": "[REDACTED_SECRET]"},
                "response_headers": {},
                "response_body_snippet": "OK",
                "duration_ms": 12.34
            }) + "\n")
            temp_path = tf.name

        try:
            logs = load_audit_logs(log_file=temp_path)
            self.assertEqual(len(logs), 1)
            self.assertEqual(logs[0]["endpoint"], "/api/Quantitys")
            self.assertEqual(logs[0]["status_code"], 200)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
