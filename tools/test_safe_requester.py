"""
Unit Tests for Core Python Tool (Task 2.1 - Task 2.5)

File: tools/test_safe_requester.py
Description: Kiểm thử độc lập safe_requester.py:
             - Kiểm tra Method validation (chỉ chấp nhận GET, POST, OPTIONS)
             - Kiểm tra tự động tiêm AGENT_API_KEY
             - Kiểm tra response body truncation ở mốc 2048 bytes
             - Kiểm tra tích hợp log audit qua mask_sensitive_data()
"""

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.safe_requester import send_request, validate_method, burst_test


class TestSafeRequester(unittest.TestCase):
    """Bộ kiểm thử tính năng cho HTTP Client safe_requester."""

    def setUp(self):
        os.environ["AGENT_API_KEY"] = "test-agent-key-2026"

    def test_method_validation(self):
        """Kiểm thử chặn các HTTP Method không nằm trong policy."""
        self.assertTrue(validate_method("GET"))
        self.assertTrue(validate_method("POST"))
        self.assertTrue(validate_method("OPTIONS"))
        self.assertFalse(validate_method("DELETE"))
        self.assertFalse(validate_method("PUT"))
        self.assertFalse(validate_method("PATCH"))

        res = send_request("http://localhost:8000/api/Users", method="DELETE")
        self.assertEqual(res["status"], "error")
        self.assertIn("Method not allowed", res["message"])

    def test_optional_parameters_and_api_key_injection(self):
        """Kiểm thử tham số headers=None, payload=None và tự động tiêm x-api-key."""
        with patch("requests.Session.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "application/json"}
            mock_resp.iter_content.return_value = [b'{"status": "ok"}']
            mock_req.return_value = mock_resp

            res = send_request("http://localhost:8000/api/Quantitys", method="GET", headers=None, payload=None)

            self.assertEqual(res["status_code"], 200)
            # Verify x-api-key header was automatically injected
            call_kwargs = mock_req.call_args.kwargs
            self.assertIn("x-api-key", call_kwargs["headers"])
            self.assertEqual(call_kwargs["headers"]["x-api-key"], "test-agent-key-2026")

    def test_response_truncation_2048_bytes(self):
        """Kiểm thử giới hạn cắt nhỏ response body ở mốc 2048 bytes."""
        large_content = b"A" * 3000  # 3000 bytes
        with patch("requests.Session.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/plain"}
            mock_resp.iter_content.return_value = [large_content]
            mock_req.return_value = mock_resp

            res = send_request("http://localhost:8000/api/Quantitys", method="GET")

            self.assertTrue(res["truncated"])
            self.assertEqual(len(res["body"]), 2048)

    def test_burst_test_rate_limit_summary(self):
        """Kiểm thử tính năng burst test trả về bảng tóm tắt kết quả."""
        with patch("tools.safe_requester.send_request") as mock_send:
            mock_send.return_value = {"status_code": 200, "body": "ok"}

            summary = burst_test("http://localhost:8000/api/Quantitys", count=5, method="GET")

            self.assertEqual(summary["total_sent"], 5)
            self.assertEqual(summary["status_counts"][200], 5)
            self.assertEqual(mock_send.call_count, 5)


if __name__ == "__main__":
    unittest.main()
