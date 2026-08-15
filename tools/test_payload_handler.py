"""
Unit Tests for Payload Handler & Guardrails (Task 3.1 - Task 3.3)

File: tools/test_payload_handler.py
Description: Kiểm thử độc lập bộ nạp payload safe:
             - Tra cứu payload từ payloads.json dựa trên category & value
             - Tự sinh 1.5MB string trong RAM khi category là oversized_payload
             - Từ chối payload_value không nằm trong danh sách đã duyệt
"""

import unittest
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.safe_requester import resolve_safe_payload, TOOL_SCHEMA


class TestPayloadHandler(unittest.TestCase):
    """Bộ kiểm thử tính năng cho Safe Payload Resolver và Function Calling Schema."""

    def test_resolve_normal_category_default_value(self):
        """Kiểm thử lấy giá trị mặc định đầu tiên khi không truyền payload_value."""
        payload = resolve_safe_payload(category="special_chars", value=None)
        self.assertEqual(payload, "' \" < > & ; --")

    def test_resolve_valid_specific_value(self):
        """Kiểm thử chọn giá trị cụ thể hợp lệ trong nhóm."""
        payload = resolve_safe_payload(category="special_chars", value="<script>alert(1)</script>")
        self.assertEqual(payload, "<script>alert(1)</script>")

    def test_reject_unapproved_payload_value(self):
        """Kiểm thử từ chối giá trị không nằm trong danh sách được duyệt."""
        with self.assertRaises(ValueError) as ctx:
            resolve_safe_payload(category="special_chars", value="MALICIOUS_UNAPPROVED_PAYLOAD")
        self.assertIn("not found in approved list", str(ctx.exception))

    def test_oversized_payload_auto_generation(self):
        """Kiểm thử tự sinh chuỗi 1.5MB trong RAM cục bộ khi chọn oversized_payload."""
        payload = resolve_safe_payload(category="oversized_payload", value=None)
        self.assertIsInstance(payload, str)
        self.assertGreaterEqual(len(payload), 1500000)
        self.assertTrue(payload.startswith("A"))

    def test_tool_schema_structure(self):
        """Kiểm thử cấu hình Tool Schema (Function Calling) đủ 2 tham số."""
        self.assertIn("payload_category", TOOL_SCHEMA["parameters"]["properties"])
        self.assertIn("payload_value", TOOL_SCHEMA["parameters"]["properties"])
        self.assertIn("oversized_payload", TOOL_SCHEMA["parameters"]["properties"]["payload_category"]["enum"])


if __name__ == "__main__":
    unittest.main()
