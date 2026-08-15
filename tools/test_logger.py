"""
Unit Tests for Audit Logger Engine (Task 1.2 & 1.3)

File: tools/test_logger.py
Description: Kiểm thử độc lập hàm log_audit_event():
             - Ghi dòng JSONL chuẩn vào file logs/gateway_audit.jsonl
             - Đảm bảo tự động gọi mask_sensitive_data() lên cả request_headers, response_headers và response_body
             - Kiểm tra tính đầy đủ của các thuộc tính ISO8601 timestamp, duration_ms, status_code.
"""

import unittest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.logger import log_audit_event


class TestLogger(unittest.TestCase):
    """Bộ kiểm thử cho hàm ghi vết Audit Log."""

    def setUp(self):
        # Tạo file tạm để kiểm thử log
        self.test_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.test_dir.name, "test_audit.jsonl")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_log_audit_event_structure_and_masking(self):
        """Kiểm thử cấu trúc JSONL và đảm bảo secret bị mask 100% khi ghi log."""
        req_headers = {"x-api-key": "secret-key-999", "User-Agent": "TestAgent"}
        res_headers = {"Content-Type": "application/json", "Set-Cookie": "sessionid=xyz123"}
        res_body = {"status": "ok", "user_email": "tester@example.com"}

        logged_entry = log_audit_event(
            endpoint="/api/Quantitys",
            method="GET",
            status_code=200,
            request_headers=req_headers,
            response_headers=res_headers,
            response_body_snippet=res_body,
            duration_ms=45.2,
            log_file=self.log_file
        )

        # Kiểm tra dữ liệu được trả về
        self.assertEqual(logged_entry["endpoint"], "/api/Quantitys")
        self.assertEqual(logged_entry["method"], "GET")
        self.assertEqual(logged_entry["status_code"], 200)
        self.assertEqual(logged_entry["request_headers"]["x-api-key"], "[REDACTED_SECRET]")
        self.assertEqual(logged_entry["response_headers"]["Set-Cookie"], "[REDACTED_SECRET]")
        self.assertEqual(logged_entry["response_body_snippet"]["user_email"], "[REDACTED_EMAIL]")

        # Kiểm tra file JSONL được ghi thực tế
        self.assertTrue(os.path.exists(self.log_file))
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertIn("timestamp", data)
            self.assertEqual(data["duration_ms"], 45.2)
            self.assertNotIn("secret-key-999", lines[0])
            self.assertNotIn("sessionid=xyz123", lines[0])


if __name__ == "__main__":
    unittest.main()
