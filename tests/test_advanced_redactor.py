"""
Project Sentinel - DevSecOps & AI Gateway
Module: Unit Tests for Advanced PII & Redactor Engine (Plan 6)
File: tests/test_advanced_redactor.py

Mục đích:
    Kiểm thử tính năng nhận diện và che giấu tự động:
    - Số điện thoại (VN & Quốc tế).
    - Thông tin định danh cá nhân PII (CCCD/CMND).
    - Thẻ thanh toán quốc tế (Credit Card / PAN).
    - Mật khẩu & Token nội dòng (Inline Secrets, URI credentials).
    - Khử khuẩn mảng messages trước khi gửi LLM (sanitize_llm_messages).
    - Đảm bảo các số thông thường (HTTP status code, timestamp, count) không bị over-masking.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.redactor import mask_sensitive_data, sanitize_llm_messages


class TestAdvancedRedactor(unittest.TestCase):
    """Bộ kiểm thử tính chính xác của bộ lọc PII và Sensitive Data nâng cao."""

    def test_mask_vietnamese_and_intl_phone_numbers(self):
        """Kiểm thử nhận diện và che số điện thoại Việt Nam và quốc tế đa định dạng."""
        test_cases = [
            ("Liên hệ SĐT 0912345678 để hỗ trợ", "Liên hệ SĐT [REDACTED_PHONE] để hỗ trợ"),
            ("Gọi ngay 0912 345 678 khi có sự cố", "Gọi ngay [REDACTED_PHONE] khi có sự cố"),
            ("Số hotline: 0912-345-678", "Số hotline: [REDACTED_PHONE]"),
            ("Đầu số quốc tế: +84912345678", "Đầu số quốc tế: [REDACTED_PHONE]"),
            ("Định dạng quốc tế có dấu cách: +84 988 123 456", "Định dạng quốc tế có dấu cách: [REDACTED_PHONE]"),
            ("Điện thoại bàn Hà Nội: (024) 3755 1234", "Điện thoại bàn Hà Nội: [REDACTED_PHONE]")
        ]
        for raw, expected in test_cases:
            result = mask_sensitive_data(raw)
            self.assertEqual(result, expected, f"Thất bại với mẫu: {raw}")

    def test_mask_pii_and_credit_cards(self):
        """Kiểm thử nhận diện và che CCCD 12 số, CMND 9 số và Thẻ tín dụng 16 số."""
        # CCCD 12 số
        raw_cccd = "Số căn cước công dân: 001201012345 cấp tại Hà Nội"
        self.assertEqual(
            mask_sensitive_data(raw_cccd),
            "Số căn cước công dân: [REDACTED_PII] cấp tại Hà Nội"
        )

        # CMND 9 số
        raw_cmnd = "Số CMND cũ: 123456789"
        self.assertEqual(
            mask_sensitive_data(raw_cmnd),
            "Số CMND cũ: [REDACTED_PII]"
        )

        # Thẻ tín dụng có dấu gạch nối
        raw_card_dash = "Thanh toán qua thẻ Visa 4532-1234-5678-9012 tại quầy"
        self.assertEqual(
            mask_sensitive_data(raw_card_dash),
            "Thanh toán qua thẻ Visa [REDACTED_CREDIT_CARD] tại quầy"
        )

        # Thẻ tín dụng viết liền
        raw_card_plain = "Số thẻ: 4532123456789012"
        self.assertEqual(
            mask_sensitive_data(raw_card_plain),
            "Số thẻ: [REDACTED_CREDIT_CARD]"
        )

    def test_mask_inline_secrets_and_connection_strings(self):
        """Kiểm thử che mật khẩu, token nội dòng và URI connection string."""
        raw_pass = "Vui lòng nhập password=SuperSecretPassword123 để tiếp tục"
        self.assertEqual(
            mask_sensitive_data(raw_pass),
            "Vui lòng nhập password=[REDACTED_PASSWORD] để tiếp tục"
        )

        raw_api_key = "Thiết lập api_key=sk-ant-api03-abcdef1234567890"
        self.assertEqual(
            mask_sensitive_data(raw_api_key),
            "Thiết lập api_key=[REDACTED_SECRET]"
        )

        raw_uri = "Kết nối CSDL qua postgres://db_admin:SuperSecretPass@10.0.0.5:5432/app_db"
        self.assertEqual(
            mask_sensitive_data(raw_uri),
            "Kết nối CSDL qua postgres://db_admin:[REDACTED_PASSWORD]@10.0.0.5:5432/app_db"
        )

    def test_sanitize_llm_messages(self):
        """Kiểm thử hàm khử khuẩn toàn diện mảng messages theo format OpenAI."""
        messages = [
            {
                "role": "system",
                "content": "Bạn là AI Agent. Tuyệt đối không rò rỉ token=secret_agent_token."
            },
            {
                "role": "user",
                "content": "Hãy kiểm tra email user@juice-sh.op với SĐT 0912345678 và thẻ 4532-1234-5678-9012."
            },
            {
                "role": "assistant",
                "content": "Tôi đang gửi request qua Gateway với api_key=super_api_key."
            }
        ]

        sanitized = sanitize_llm_messages(messages)

        # Kiểm tra System message
        self.assertIn("token=[REDACTED_TOKEN]", sanitized[0]["content"])
        self.assertNotIn("secret_agent_token", sanitized[0]["content"])

        # Kiểm tra User message
        self.assertIn("[REDACTED_EMAIL]", sanitized[1]["content"])
        self.assertIn("[REDACTED_PHONE]", sanitized[1]["content"])
        self.assertIn("[REDACTED_CREDIT_CARD]", sanitized[1]["content"])
        self.assertNotIn("user@juice-sh.op", sanitized[1]["content"])
        self.assertNotIn("0912345678", sanitized[1]["content"])
        self.assertNotIn("4532-1234-5678-9012", sanitized[1]["content"])

        # Kiểm tra Assistant message
        self.assertIn("api_key=[REDACTED_SECRET]", sanitized[2]["content"])
        self.assertNotIn("super_api_key", sanitized[2]["content"])

    def test_safe_numbers_and_timestamps_not_overmasked(self):
        """Đảm bảo các con số thông thường (Status code, count, timestamp) không bị che nhầm."""
        safe_text = "Request tới /api/Quantitys trả về status 200 trong 45 ms với 25 requests vào lúc 2026-08-19."
        masked = mask_sensitive_data(safe_text)
        self.assertEqual(masked, safe_text)


if __name__ == "__main__":
    unittest.main()
