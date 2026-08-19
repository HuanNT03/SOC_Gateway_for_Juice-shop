"""
Unit Tests for AI Security Agent Engine (Task 4.1 - Task 4.4)

File: tests/test_agent.py
"""

import unittest
from unittest.mock import patch
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agent.agent import analyze_user_request, generate_proposal, format_agent_report


class TestSecurityAgent(unittest.TestCase):
    """Bộ kiểm thử cho AI Security Agent."""

    def test_analyze_rate_limit_request(self):
        """Kiểm thử nhận diện yêu cầu thử rate limit."""
        scenario = analyze_user_request("Hãy kiểm tra rate limit của endpoint /api/Quantitys")
        self.assertEqual(scenario, "rate_limit")

    def test_analyze_forbidden_endpoint_request(self):
        """Kiểm thử nhận diện yêu cầu thử endpoint bị cấm."""
        scenario = analyze_user_request("Thử truy cập vào endpoint admin /rest/admin/application-version")
        self.assertEqual(scenario, "forbidden_endpoint")

    def test_analyze_oversized_payload_request(self):
        """Kiểm thử nhận diện yêu cầu thử payload ngoại cỡ > 1MB."""
        scenario = analyze_user_request("Gửi file lớn hoặc oversized payload để test gateway")
        self.assertEqual(scenario, "oversized_payload")

    def test_analyze_special_chars_request(self):
        """Kiểm thử nhận diện yêu cầu thử ký tự đặc biệt XSS/Injection."""
        scenario = analyze_user_request("Thử chèn ký tự đặc biệt <script>alert(1)</script> vào search")
        self.assertEqual(scenario, "special_chars")

    @patch("agent.agent.generate_proposal_llm", return_value=None)
    def test_generate_proposal_structure(self, mock_llm):
        """Kiểm thử cấu trúc đề xuất kịch bản kiểm thử từ payloads.json."""
        proposal = generate_proposal("special_chars")
        self.assertEqual(proposal["payload_category"], "special_chars")
        self.assertIn("url", proposal)
        self.assertIn("method", proposal)

    @patch("agent.agent.analyze_burst_test_with_llm", return_value=None)
    @patch("agent.agent.analyze_response_with_llm", return_value=None)
    def test_format_agent_report_mindset_guardrails(self, mock_llm_analysis, mock_burst_analysis):
        """Kiểm thử báo cáo an ninh theo Mindset Guardrails cho mã 413, 429, 403 và Burst Test."""
        # 413 Payload Too Large
        report_413 = format_agent_report({"status_code": 413, "endpoint": "/api/Quantitys", "body": "Too Large"})
        self.assertIn("đúng thiết kế", report_413.lower())
        self.assertIn("413", report_413)

        # 429 Too Many Requests (Single Request)
        report_429 = format_agent_report({"status_code": 429, "endpoint": "/api/Quantitys", "body": "Rate Limit Exceeded"})
        self.assertIn("đúng thiết kế", report_429.lower())
        self.assertIn("rate-limiting", report_429.lower())

        # 403 Forbidden
        report_403 = format_agent_report({"status_code": 403, "endpoint": "/rest/admin/app", "body": "Forbidden"})
        self.assertIn("đúng thiết kế", report_403.lower())
        self.assertIn("acl", report_403.lower())

        # Burst Rate Limit Test (25 requests)
        burst_result = {
            "total_sent": 25,
            "status_counts": {200: 20, 429: 5},
            "responses": [{"status_code": 200, "endpoint": "/api/Quantitys", "method": "GET"}]
        }
        report_burst = format_agent_report(burst_result)
        self.assertIn("đúng thiết kế", report_burst.lower())
        self.assertIn("rate-limiting", report_burst.lower())


if __name__ == "__main__":
    unittest.main()
