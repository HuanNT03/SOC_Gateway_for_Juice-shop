"""
Project Sentinel - DevSecOps & AI Gateway
Module: Unit Tests for Streamlit UI Helper Functions (Plan 9)
File: tests/test_ui.py

Mục đích:
    Kiểm thử các hàm phụ trợ trên giao diện Web UI Dashboard:
    - Tạo badge HTML cho HTTP Status Codes (200, 401, 403, 405, 413, 429, 0).
    - Tạo badge HTML cho các mức độ rủi ro (LOW, MEDIUM, HIGH, CRITICAL).
    - Nạp nhật ký Audit Logs từ tệp JSONL có chứa trường approval_status.
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agent.ui import load_audit_logs, get_status_badge_html, get_risk_badge_html


class TestStreamlitUI(unittest.TestCase):
    """Bộ kiểm thử cho Streamlit UI helpers."""

    def test_get_status_badge_html(self):
        """Kiểm thử HTML badge trả về theo từng status code."""
        badge_200 = get_status_badge_html(200)
        self.assertIn("200 ok", badge_200.lower())

        badge_403 = get_status_badge_html(403)
        self.assertIn("403", badge_403)
        self.assertIn("forbidden", badge_403.lower())

        badge_413 = get_status_badge_html(413)
        self.assertIn("413", badge_413)
        self.assertIn("payload too large", badge_413.lower())

        badge_429 = get_status_badge_html(429)
        self.assertIn("429", badge_429)
        self.assertIn("rate limit", badge_429.lower())

        badge_405 = get_status_badge_html(405)
        self.assertIn("405", badge_405)
        self.assertIn("method not allowed", badge_405.lower())

        badge_0 = get_status_badge_html(0)
        self.assertIn("cancelled/blocked", badge_0.lower())

    def test_get_risk_badge_html(self):
        """Kiểm thử HTML badge cho các cấp độ rủi ro (LOW, MEDIUM, HIGH, CRITICAL)."""
        badge_low = get_risk_badge_html("LOW")
        self.assertIn("LOW", badge_low)
        self.assertIn("An toàn", badge_low)

        badge_med = get_risk_badge_html("MEDIUM")
        self.assertIn("MEDIUM", badge_med)
        self.assertIn("Cần Duyệt", badge_med)

        badge_high = get_risk_badge_html("HIGH")
        self.assertIn("HIGH", badge_high)
        self.assertIn("Rủi ro Hạ tầng", badge_high)

        badge_crit = get_risk_badge_html("CRITICAL")
        self.assertIn("CRITICAL", badge_crit)
        self.assertIn("Tấn công", badge_crit)

    def test_load_audit_logs(self):
        """Kiểm thử đọc và nạp tệp log JSONL có kèm approval_status."""
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".jsonl") as tf:
            tf.write(json.dumps({
                "timestamp": "2026-08-15T10:00:00Z",
                "endpoint": "/api/Quantitys",
                "method": "POST",
                "status_code": 413,
                "request_headers": {"x-api-key": "[REDACTED_SECRET]"},
                "response_headers": {},
                "response_body_snippet": "Payload Too Large",
                "duration_ms": 12.34,
                "approval_status": "APPROVED"
            }) + "\n")
            tf.write(json.dumps({
                "timestamp": "2026-08-15T10:01:00Z",
                "endpoint": "/api/Quantitys",
                "method": "POST",
                "status_code": 0,
                "request_headers": {},
                "response_headers": {},
                "response_body_snippet": "ACTION_REJECTED_BY_USER",
                "duration_ms": 0.0,
                "approval_status": "REJECTED_BY_USER"
            }) + "\n")
            temp_path = tf.name

        try:
            logs = load_audit_logs(log_file=temp_path)
            self.assertEqual(len(logs), 2)
            # Bản ghi mới nhất xếp trước
            self.assertEqual(logs[0]["approval_status"], "REJECTED_BY_USER")
            self.assertEqual(logs[0]["status_code"], 0)
            self.assertEqual(logs[1]["approval_status"], "APPROVED")
            self.assertEqual(logs[1]["status_code"], 413)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_default_probe_response_structure(self):
        """Kiểm thử cấu trúc JSON hợp lệ và đủ trường của DEFAULT_PROBE_RESPONSE."""
        from agent.ui import DEFAULT_PROBE_RESPONSE
        parsed = json.loads(DEFAULT_PROBE_RESPONSE)
        self.assertIn("victim_profile", parsed)
        self.assertIn("malicious_injection_en", parsed)
        self.assertIn("malicious_injection_vi", parsed)
        self.assertIn("email", parsed["victim_profile"])
        self.assertIn("phone_vn", parsed["victim_profile"])
        self.assertIn("credit_card", parsed["victim_profile"])


if __name__ == "__main__":
    unittest.main()
