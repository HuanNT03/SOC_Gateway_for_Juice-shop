"""
Unit Tests for Redactor Engine (Task 1.1)

File: tests/test_redactor.py
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.redactor import mask_sensitive_data


class TestRedactor(unittest.TestCase):
    """Bộ kiểm thử tính chính xác và an toàn của hàm mask_sensitive_data."""

    def test_mask_sensitive_headers(self):
        """Kiểm thử ẩn các header nhạy cảm (không phân biệt chữ hoa/thường)."""
        headers = {
            "Host": "localhost:8000",
            "x-api-key": "secret-key-12345",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            "Set-Cookie": "connect.sid=s%3A12345; Path=/; HttpOnly",
            "User-Agent": "SentinelTester/1.0"
        }
        masked = mask_sensitive_data(headers)
        
        self.assertEqual(masked["Host"], "localhost:8000")
        self.assertEqual(masked["User-Agent"], "SentinelTester/1.0")
        self.assertEqual(masked["x-api-key"], "[REDACTED_SECRET]")
        self.assertIn("[REDACTED_JWT]", masked["Authorization"])
        self.assertEqual(masked["Set-Cookie"], "[REDACTED_SECRET]")

    def test_mask_nested_json_body(self):
        """Kiểm thử quét đệ quy cấu trúc JSON lồng nhau nhiều tầng."""
        body = {
            "status": "success",
            "data": {
                "user": {
                    "email": "huan.test@example.com",
                    "password": "supersecretpassword123",
                    "roles": ["admin", "tester"]
                },
                "authentication": {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImVtYWlsIjoidGVzdEB2bnUuZWR1LnZuIn0.signature12345"
                }
            },
            "logs": [
                {"secret": "api-token-value-99"},
                {"public_info": "hello world"}
            ]
        }
        masked = mask_sensitive_data(body)
        
        self.assertEqual(masked["data"]["user"]["email"], "[REDACTED_EMAIL]")
        self.assertEqual(masked["data"]["user"]["password"], "[REDACTED_SECRET]")
        self.assertEqual(masked["data"]["authentication"]["token"], "[REDACTED_SECRET]")
        self.assertEqual(masked["logs"][0]["secret"], "[REDACTED_SECRET]")
        self.assertEqual(masked["logs"][1]["public_info"], "hello world")

    def test_regex_email_and_jwt_in_raw_string(self):
        """Kiểm thử nhận diện Regex Email và JWT thuần trong chuỗi văn bản tự do."""
        raw_text = "User admin@juice-sh.op logged in with token eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjV9.signatureabc"
        masked = mask_sensitive_data(raw_text)
        
        self.assertNotIn("admin@juice-sh.op", masked)
        self.assertNotIn("signatureabc", masked)
        self.assertIn("[REDACTED_EMAIL]", masked)
        self.assertIn("[REDACTED_JWT]", masked)

    def test_primitive_data_types_safety(self):
        """Kiểm thử an toàn với các kiểu dữ liệu nguyên thủy (int, float, bool, None)."""
        self.assertEqual(mask_sensitive_data(12345), 12345)
        self.assertEqual(mask_sensitive_data(3.14159), 3.14159)
        self.assertEqual(mask_sensitive_data(True), True)
        self.assertIsNone(mask_sensitive_data(None))


if __name__ == "__main__":
    unittest.main()
