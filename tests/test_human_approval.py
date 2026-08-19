"""
Project Sentinel - DevSecOps & AI Gateway
Module: Unit Tests for Human-in-the-Loop (HITL) Approval Engine (Plan 8)
File: tests/test_human_approval.py

Mục đích:
    Kiểm thử cơ chế chốt chặn an toàn có sự can thiệp của con người:
    - Đánh giá phân loại rủi ro (Risk Assessment Engine) theo phương thức, payload và số lượng request.
    - Hộp thoại tương tác dòng lệnh (Interactive CLI Approval).
    - Xử lý phân nhánh chấp thuận (Approve) và từ chối (Reject - Fail-closed).
    - Đảm bảo khi người dùng từ chối, tuyệt đối không có network socket/request nào được gửi đến Gateway.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.safe_requester import assess_request_risk, prompt_cli_approval
from agent.agent import execute_proposal, format_agent_report


class TestHumanInTheLoopApproval(unittest.TestCase):
    """Bộ kiểm thử cho Human-in-the-Loop Approval Engine."""

    def test_assess_request_risk_categories(self):
        """Kiểm thử độ chính xác của Risk Assessment Engine với các loại request khác nhau."""
        # 1. Request GET thông thường an toàn (Allowlist) -> LOW (Không cần duyệt)
        low_risk = assess_request_risk("GET", "/api/Quantitys", payload_category="long_string", count=1)
        self.assertFalse(low_risk["requires_approval"])
        self.assertEqual(low_risk["risk_level"], "LOW")
        self.assertEqual(len(low_risk["risk_factors"]), 0)

        # 2. Request POST thay đổi dữ liệu -> MEDIUM (Bắt buộc duyệt)
        post_risk = assess_request_risk("POST", "/api/Quantitys", payload_category="long_string", count=1)
        self.assertTrue(post_risk["requires_approval"])
        self.assertEqual(post_risk["risk_level"], "MEDIUM")
        self.assertTrue(any("POST" in f for f in post_risk["risk_factors"]))

        # 3. Request chứa ký tự đặc biệt / Injection Probe -> MEDIUM (Bắt buộc duyệt)
        special_risk = assess_request_risk("GET", "/rest/products/search", payload_category="special_chars", count=1)
        self.assertTrue(special_risk["requires_approval"])
        self.assertEqual(special_risk["risk_level"], "MEDIUM")
        self.assertTrue(any("special_chars" in f for f in special_risk["risk_factors"]))

        # 4. Request Payload ngoại cỡ > 1MB -> HIGH (Bắt buộc duyệt)
        oversized_risk = assess_request_risk("POST", "/api/Quantitys", payload_category="oversized_payload", count=1)
        self.assertTrue(oversized_risk["requires_approval"])
        self.assertEqual(oversized_risk["risk_level"], "HIGH")
        self.assertTrue(any("oversized" in f.lower() for f in oversized_risk["risk_factors"]))

        # 5. Burst Test số lượng lớn (count > 20) -> HIGH (Bắt buộc duyệt)
        burst_risk = assess_request_risk("GET", "/api/Quantitys", payload_category="long_string", count=25)
        self.assertTrue(burst_risk["requires_approval"])
        self.assertEqual(burst_risk["risk_level"], "HIGH")
        self.assertTrue(any("burst" in f.lower() for f in burst_risk["risk_factors"]))

    @patch("builtins.input", side_effect=["y", "yes", "Y", "YES"])
    def test_prompt_cli_approval_yes_cases(self, mock_input):
        """Kiểm thử khi người dùng nhập các biến thể chấp thuận (y/yes/Y)."""
        assessment = assess_request_risk("POST", "/api/Quantitys", "oversized_payload", 1)
        
        self.assertTrue(prompt_cli_approval(assessment))
        self.assertTrue(prompt_cli_approval(assessment))
        self.assertTrue(prompt_cli_approval(assessment))
        self.assertTrue(prompt_cli_approval(assessment))

    @patch("builtins.input", side_effect=["n", "", "no", "invalid", EOFError()])
    def test_prompt_cli_approval_no_and_fail_closed(self, mock_input):
        """Kiểm thử nguyên tắc Fail-Closed: Mặc định từ chối khi nhập 'n', Enter rỗng hoặc ngắt tín hiệu."""
        assessment = assess_request_risk("POST", "/api/Quantitys", "oversized_payload", 1)
        
        # Nhập 'n'
        self.assertFalse(prompt_cli_approval(assessment))
        # Bấm Enter (chuỗi rỗng) -> Từ chối mặc định
        self.assertFalse(prompt_cli_approval(assessment))
        # Nhập 'no'
        self.assertFalse(prompt_cli_approval(assessment))
        # Nhập ký tự không xác định
        self.assertFalse(prompt_cli_approval(assessment))
        # Bị EOFError / KeyboardInterrupt
        self.assertFalse(prompt_cli_approval(assessment))

    def test_auto_approve_flags_for_ci_and_testing(self):
        """Kiểm thử cơ chế tự động phê duyệt trong môi trường CI/CD hoặc cờ auto_approve."""
        assessment = assess_request_risk("POST", "/api/Quantitys", "oversized_payload", 1)

        # 1. Truyền trực tiếp auto_approve=True
        self.assertTrue(prompt_cli_approval(assessment, auto_approve=True))

        # 2. Sử dụng biến môi trường CI_MODE
        os.environ["CI_MODE"] = "true"
        try:
            self.assertTrue(prompt_cli_approval(assessment, auto_approve=False))
        finally:
            del os.environ["CI_MODE"]

        # 3. Sử dụng biến môi trường AUTO_APPROVE
        os.environ["AUTO_APPROVE"] = "true"
        try:
            self.assertTrue(prompt_cli_approval(assessment, auto_approve=False))
        finally:
            del os.environ["AUTO_APPROVE"]

    @patch("agent.agent.prompt_cli_approval", return_value=True)
    @patch("agent.agent.send_request")
    def test_execute_proposal_when_user_approves(self, mock_send, mock_prompt):
        """Kiểm thử khi người dùng đồng ý: Request được gửi qua mạng bình thường."""
        mock_send.return_value = {
            "status": "error",
            "status_code": 413,
            "endpoint": "/api/Quantitys",
            "method": "POST",
            "body": "Payload Too Large",
            "duration_ms": 12.5
        }

        proposal = {
            "scenario_name": "Kiểm thử Payload ngoại cỡ",
            "url": "/api/Quantitys",
            "method": "POST",
            "count": 1,
            "payload_category": "oversized_payload",
            "payload_value": None
        }

        result = execute_proposal(proposal, interactive=True)

        # Đảm bảo đã hiển thị xác nhận và đã gọi send_request
        mock_prompt.assert_called_once()
        mock_send.assert_called_once()
        self.assertEqual(result.get("status_code"), 413)

    @patch("agent.agent.prompt_cli_approval", return_value=False)
    @patch("agent.agent.send_request")
    def test_execute_proposal_when_user_rejects(self, mock_send, mock_prompt):
        """Kiểm thử khi người dùng từ chối: Request bị hủy ngay lập tức và KHÔNG có network call nào."""
        proposal = {
            "scenario_name": "Kiểm thử Payload ngoại cỡ",
            "url": "/api/Quantitys",
            "method": "POST",
            "count": 1,
            "payload_category": "oversized_payload",
            "payload_value": None
        }

        result = execute_proposal(proposal, interactive=True)

        # Xác nhận prompt đã được gọi nhưng send_request TUYỆT ĐỐI KHÔNG được gọi
        mock_prompt.assert_called_once()
        mock_send.assert_not_called()

        # Kiểm tra cấu trúc phản hồi bị từ chối
        self.assertEqual(result.get("status"), "rejected")
        self.assertEqual(result.get("status_code"), 0)
        self.assertTrue(result.get("is_rejected_by_user"))

        # Báo cáo an ninh hiển thị rõ thông báo hủy bỏ
        report = format_agent_report(result)
        self.assertIn("HUMAN-IN-THE-LOOP REJECTION", report)
        self.assertIn("hủy lệnh thành công", report)


if __name__ == "__main__":
    unittest.main()
