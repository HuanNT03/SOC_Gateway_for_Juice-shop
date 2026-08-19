"""
Project Sentinel - DevSecOps & AI Gateway
Module: Audit Logger Engine (tools/logger.py)

Mục đích:
    Ghi vết nhật ký kiểm toán (Audit Log) theo chuẩn định dạng JSON Lines (.jsonl).
    Tự động áp dụng bộ lọc mask_sensitive_data() lên Request Headers, Response Headers và Response Body
    trước khi ghi tệp nhằm đảm bảo không bao giờ rò rỉ API Key, Session Cookies hoặc JWT Tokens vào tệp log.

Đầu vào (Inputs):
    endpoint (str): Đồng thời là URL path của request (VD: "/api/Quantitys").
    method (str): Phương thức HTTP (GET, POST, OPTIONS).
    status_code (int): Mã trạng thái HTTP trả về (200, 401, 403, 413, 429, v.v.).
    request_headers (dict): Các header của request.
    response_headers (dict): Các header nhận được từ response.
    response_body_snippet (Any): Một phần response body (đã được giới hạn kích thước).
    duration_ms (float): Thời gian xử lý request (milisecond).
    log_file (str): Đường dẫn tệp ghi log (mặc định: "logs/gateway_audit.jsonl").

Đầu ra (Outputs):
    dict: Đối tượng log record chuẩn (đã được làm sạch hoàn toàn secret).

Xử lý Edge Cases:
    - Tạo tự động thư mục cha (VD: logs/) nếu chưa tồn tại.
    - Đảm bảo ghi đệm thread-safe/append mode để không ghi đè dữ liệu log cũ.
    - Chuyển đổi timestamp sang chuẩn ISO8601 UTC.
"""

import os
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
try:
    from redactor import mask_sensitive_data
except ImportError:
    from tools.redactor import mask_sensitive_data

DEFAULT_LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "logs", "gateway_audit.jsonl")
)


def log_audit_event(
    endpoint: str,
    method: str,
    status_code: int,
    request_headers: Dict[str, Any],
    response_headers: Dict[str, Any],
    response_body_snippet: Any,
    duration_ms: float,
    log_file: str = DEFAULT_LOG_FILE,
    approval_status: Optional[str] = None
) -> Dict[str, Any]:
    """Tạo và ghi 1 dòng JSONL Audit record an toàn vào file log.

    Inputs & Outputs xem trong docstring module.
    """
    # Làm sạch toàn bộ dữ liệu trước khi ghi log
    masked_req_headers = mask_sensitive_data(request_headers or {})
    masked_res_headers = mask_sensitive_data(response_headers or {})
    masked_res_body = mask_sensitive_data(response_body_snippet)

    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "request_headers": masked_req_headers,
        "response_headers": masked_res_headers,
        "response_body_snippet": masked_res_body,
        "duration_ms": round(duration_ms, 2)
    }

    if approval_status:
        audit_entry["approval_status"] = approval_status

    # Đảm bảo thư mục đích tồn tại
    log_dir = os.path.dirname(os.path.abspath(log_file))
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    # Ghi nối (append) dòng JSONL
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")
    except Exception as err:
        # In cảnh báo nhẹ nếu lỗi ghi file log (không làm sập luồng chính)
        print(f"[LOG WARNING] Failed to write audit log: {err}")

    return audit_entry
