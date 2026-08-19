"""
Project Sentinel - DevSecOps & AI Gateway
Module: Core HTTP Client Tool (tools/safe_requester.py)

Mục đích:
    Cung cấp công cụ gửi HTTP Request an toàn qua Kong API Gateway (Port 8000).
    - Giới hạn phương thức HTTP (Chỉ cho phép GET, POST, OPTIONS).
    - Tự động tiêm API Key từ môi trường (AGENT_API_KEY) vào header x-api-key.
    - Áp đặt Timeout 7 giây phòng chống race condition với 5s Gateway timeout.
    - Giới hạn cắt nhỏ Response body ở mốc 2048 bytes (2KB) giải nén gzip an toàn qua iter_content().
    - Tích hợp tự động với logger.py và redactor.py ghi log audit JSONL đã làm sạch bí mật.
    - Cung cấp tính năng burst test kiểm thử giới hạn tốc độ (Rate Limit).

Đầu vào (Inputs):
    url (str): Endpoint mục tiêu (VD: "http://localhost:8000/api/Quantitys" hoặc "/api/Quantitys").
    method (str): Phương thức HTTP ("GET", "POST", "OPTIONS"). Mặc định: "GET".
    headers (dict, optional): Headers bổ sung. Mặc định: None (tự tạo dict rỗng).
    payload (Any, optional): Dữ liệu gửi đi (JSON body/string). Mặc định: None.
    timeout (float): Thời gian chờ kết nối (giây). Mặc định: 7.0.

Đầu ra (Outputs):
    dict: Phản hồi chuẩn chứa status_code, body, headers, duration_ms, truncated (boolean).

Xử lý Edge Cases:
    - Nếu URL là đường dẫn tương đối (VD: "/api/Quantitys"), tự bổ sung tiền tố "http://localhost:8000".
    - Xử lý các lỗi kết nối/timeout bằng try-except, trả về dict báo lỗi chuẩn thay vì làm ngắt kết nối Agent.
"""

import os
import sys
import json
import time
import argparse
import requests
from typing import Any, Dict, Optional
from dotenv import load_dotenv

# Tự động nạp cấu hình môi trường từ .env
load_dotenv()

# Nạp module logger và redactor từ thư mục local
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from redactor import mask_sensitive_data
from logger import log_audit_event

# Phương thức HTTP được phép theo chính sách an toàn
ALLOWED_METHODS = {"GET", "POST", "OPTIONS"}
DEFAULT_GATEWAY_HOST = os.getenv("GATEWAY_HOST", "http://localhost:8000")
DEFAULT_TIMEOUT = 7.0  # 7 giây (5s Kong timeout + 2s buffer margin)
MAX_RESPONSE_BYTES = 2048  # 2KB

PAYLOADS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "payloads.json")
)

# JSON Schema (Function Calling Constraint) dành cho AI Agent
TOOL_SCHEMA = {
    "name": "send_request",
    "description": (
        "Gửi HTTP request kiểm thử an toàn qua Kong API Gateway (Port 8000). "
        "Tool nhận đầu vào (url, method, payload_category, payload_value, count), "
        "tự động tiêm header x-api-key từ môi trường, thực thi request và làm sạch (redact) "
        "mọi dữ liệu nhạy cảm trước khi trả về kết quả. "
        "Đầu ra bao gồm: status_code (int), endpoint (str), method (str), headers (dict đã masked), "
        "body (str/json đã masked, tối đa 2KB), truncated (bool) và duration_ms (float)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Endpoint path mụcc tiêu cần kiểm thử (Ví dụ: '/api/Quantitys', '/rest/admin/application-version', '/rest/products/search')."
            },
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "OPTIONS"],
                "description": "Phương thức HTTP được phép theo chính sách an toàn (GET, POST, OPTIONS)."
            },
            "payload_category": {
                "type": "string",
                "enum": [
                    "long_string",
                    "special_chars",
                    "empty_values",
                    "type_mismatch",
                    "query_param_injection",
                    "oversized_payload"
                ],
                "description": "Nhóm payload an toàn cần sử dụng từ config/payloads.json: 'long_string' (chuỗi dài), 'special_chars' (ký tự đặc biệt), 'empty_values' (giá trị rỗng), 'type_mismatch' (sai kiểu dữ liệu), 'query_param_injection' (query string), 'oversized_payload' (tự sinh 1.5MB RAM)."
            },
            "payload_value": {
                "type": "string",
                "description": "Giá trị payload cụ thể trong nhóm đã chọn (Tùy chọn. Nếu không truyền, hệ thống sẽ tự chọn giá trị mặc định trong nhóm)."
            },
            "count": {
                "type": "integer",
                "description": "Số lượng request gửi liên tiếp (Burst Rate Limit Test). Mặc định là 1. Đặt count > 1 (VD: 25) khi người dùng muốn kiểm tra giới hạn tần suất 429 Too Many Requests."
            }
        },
        "required": ["url", "method", "payload_category"]
    }
}


def load_payloads_dict() -> Dict[str, Any]:
    """Hàm phụ trợ: Nạp từ điển safe payloads từ config/payloads.json."""
    if not os.path.exists(PAYLOADS_FILE):
        return {}
    try:
        with open(PAYLOADS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[PAYLOAD ERROR] Unable to load payloads.json: {e}")
        return {}


def resolve_safe_payload(category: str, value: Optional[str] = None) -> Any:
    """Tra cứu và xác thực payload an toàn từ config/payloads.json.

    Inputs:
        category (str): Nhóm payload ("long_string", "special_chars", "oversized_payload", v.v.).
        value (str, optional): Giá trị cụ thể mà Agent chọn.

    Outputs:
        Any: Nội dung payload đã được kiểm duyệt an toàn.

    Raises:
        ValueError: Nếu category không tồn tại hoặc value không thuộc danh sách được duyệt.
    """
    category = category.strip()
    if category == "oversized_payload":
        # Tự sinh 1.5MB trong RAM Python cục bộ (Agent không thấy chuỗi rác này)
        return "A" * 1500000

    payloads_data = load_payloads_dict()
    if category not in payloads_data:
        raise ValueError(f"Invalid payload category '{category}'. Available: {list(payloads_data.keys())}")

    approved_list = payloads_data[category]
    if not isinstance(approved_list, list) or len(approved_list) == 0:
        raise ValueError(f"No approved values in category '{category}'")

    if value is None:
        return approved_list[0]

    # Kiểm tra value có nằm trong danh sách được duyệt không
    if value in approved_list:
        return value

    raise ValueError(f"Payload value not found in approved list for category '{category}'")


def assess_request_risk(
    method: str,
    url: str,
    payload_category: Optional[str] = "long_string",
    count: int = 1
) -> Dict[str, Any]:
    """Đánh giá mức độ rủi ro của request và xác định có cần phê duyệt của con người (HITL) hay không.

    Inputs:
        method (str): Phương thức HTTP ("GET", "POST", "PUT", "DELETE", v.v.).
        url (str): Endpoint mục tiêu.
        payload_category (str, optional): Phân loại payload an toàn. Mặc định "long_string".
        count (int, optional): Số lượng request dự kiến gửi liên tiếp. Mặc định 1.

    Outputs:
        dict: {
            "requires_approval": bool,
            "risk_level": "LOW" | "MEDIUM" | "HIGH",
            "risk_factors": list[str],
            "endpoint": str,
            "method": str,
            "payload_category": str,
            "count": int,
            "purpose": str
        }
    """
    method_upper = (method or "GET").strip().upper()
    cat = (payload_category or "long_string").strip().lower()
    risk_factors = []

    # 1. Kiểm tra phương thức HTTP thay đổi dữ liệu hoặc có rủi ro
    if method_upper in ["POST", "PUT", "DELETE", "PATCH"]:
        risk_factors.append(f"Phương thức HTTP '{method_upper}' có khả năng tạo/thay đổi trạng thái dữ liệu trên server")

    # 2. Kiểm tra nhóm Payload đặc biệt
    if cat == "oversized_payload":
        risk_factors.append("Payload ngoại cỡ (oversized_payload ~1.5MB) có thể gây áp lực băng thông và tài nguyên bộ nhớ Gateway")
    elif cat in ["special_chars", "query_param_injection"]:
        risk_factors.append(f"Nhóm payload '{cat}' chứa chuỗi thăm dò ký tự đặc biệt / injection")

    # 3. Kiểm tra Burst Test lưu lượng lớn
    if count > 10:
        risk_factors.append(f"Gửi burst test tần suất cao ({count} requests) có thể kích hoạt Rate Limiter hoặc gây nghẽn dịch vụ")

    # Đánh giá mức độ rủi ro tổng hợp
    if cat == "oversized_payload" or count > 20:
        risk_level = "HIGH"
        requires_approval = True
    elif len(risk_factors) > 0:
        risk_level = "MEDIUM"
        requires_approval = True
    else:
        risk_level = "LOW"
        requires_approval = False

    # Xác định mục đích kiểm thử
    if cat == "oversized_payload":
        purpose = "Kiểm chứng Gateway chặn 413 Payload Too Large khi nhận dữ liệu ngoại cỡ > 1MB"
    elif count > 1:
        purpose = f"Kiểm chứng Gateway kích hoạt 429 Too Many Requests khi gửi {count} requests liên tiếp"
    elif "admin" in url.lower() or "application-version" in url.lower():
        purpose = "Kiểm chứng Gateway chặn 403 Forbidden theo danh sách ACL Allowlist"
    else:
        purpose = f"Kiểm thử an toàn kết nối API Gateway ({method_upper} {url})"

    return {
        "requires_approval": requires_approval,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "endpoint": url,
        "method": method_upper,
        "payload_category": cat,
        "count": count,
        "purpose": purpose
    }


def prompt_cli_approval(assessment: Dict[str, Any], auto_approve: bool = False) -> bool:
    """Hiển thị hộp thoại hỏi ý kiến phê duyệt trên giao diện dòng lệnh (CLI).

    Inputs:
        assessment (dict): Kết quả phân tích rủi ro từ assess_request_risk.
        auto_approve (bool, optional): Tự động phê duyệt (cho môi trường kiểm thử/CI).

    Outputs:
        bool: True nếu chấp thuận (y/Y hoặc auto-approve), False nếu từ chối (n/N/Enter/Timeout).
    """
    # Kiểm tra cờ tự động phê duyệt từ tham số hoặc biến môi trường CI_MODE/AUTO_APPROVE
    if auto_approve or os.getenv("CI_MODE", "").lower() == "true" or os.getenv("AUTO_APPROVE", "").lower() == "true":
        print(f"\n[HITL AUTO-APPROVED] Yêu cầu '{assessment['method']} {assessment['endpoint']}' được tự động phê duyệt (CI/Testing Mode).")
        return True

    print("\n" + "=" * 70)
    print("⚠️  [HUMAN-IN-THE-LOOP] YÊU CẦU PHÊ DUYỆT HÀNH ĐỘNG RỦI RO")
    print("=" * 70)
    print(f"- Mục tiêu kiểm thử:   {assessment['method']} {assessment['endpoint']}")
    print(f"- Nhóm Payload:        {assessment['payload_category']}")
    print(f"- Số lượng request:    {assessment['count']}")
    print(f"- Mục đích kiểm tra:   {assessment['purpose']}")
    print(f"- Mức độ rủi ro:       {assessment['risk_level']}")
    print("- Các yếu tố rủi ro:")
    for factor in assessment.get("risk_factors", []):
        print(f"   • {factor}")
    print("-" * 70)

    try:
        user_choice = input("👉 Bạn có CHẤP THUẬN gửi request này không? (y/N): ").strip().lower()
        if user_choice in ["y", "yes"]:
            print("✅ [HITL APPROVED] Người dùng đã phê duyệt. Bắt đầu gửi request...\n")
            return True
        else:
            print("🛑 [HITL REJECTED] Người dùng đã TỪ CHỐI thực thi. Hủy bỏ request an toàn.\n")
            return False
    except (EOFError, KeyboardInterrupt):
        print("\n🛑 [HITL REJECTED] Ngắt tương tác (Default to Reject).\n")
        return False


def validate_method(method: str) -> bool:
    """Kiểm tra phương thức HTTP có nằm trong danh sách được phép hay không.

    Inputs:
        method (str): Tên phương thức HTTP (case-insensitive).

    Outputs:
        bool: True nếu hợp lệ, False nếu vi phạm chính sách.
    """
    if not method or not isinstance(method, str):
        return False
    return method.strip().upper() in ALLOWED_METHODS


def _resolve_url(url: str) -> str:
    """Hàm phụ trợ: Đảm bảo URL đầy đủ tiền tố host Gateway.

    Inputs:
        url (str): URL thô (tương đối hoặc tuyệt đối).

    Outputs:
        str: URL tuyệt đối hợp lệ.
    """
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        return url
    if not url.startswith("/"):
        url = "/" + url
    return f"{DEFAULT_GATEWAY_HOST}{url}"


def send_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[Any] = None,
    timeout: float = DEFAULT_TIMEOUT,
    log_file: Optional[str] = None,
    approval_status: Optional[str] = None
) -> Dict[str, Any]:
    """Gửi HTTP request an toàn qua Gateway, tự động tiêm secret, cắt gọn response và ghi log.

    Inputs & Outputs xem trong docstring module.
    """
    method_upper = method.strip().upper() if isinstance(method, str) else "UNKNOWN"
    
    # 1. Kiểm tra chính sách HTTP Method
    if not validate_method(method_upper):
        error_msg = f"Method not allowed by Tool Policy: '{method_upper}'. Allowed: {sorted(list(ALLOWED_METHODS))}"
        return {
            "status": "error",
            "status_code": 405,
            "message": error_msg,
            "endpoint": url,
            "method": method_upper,
            "headers": {},
            "body": error_msg,
            "truncated": False,
            "duration_ms": 0.0
        }

    # 2. Xử lý URL & Headers
    target_url = _resolve_url(url)
    req_headers = dict(headers) if headers is not None else {}
    
    # 3. Tự động tiêm API Key từ môi trường (hoặc fallback mặc định)
    api_key = os.getenv("AGENT_API_KEY") or os.getenv("KONG_VAULT_ENV_AGENT_API_KEY") or "sentinel-agent-secure-key-2026"
    if "x-api-key" not in [k.lower() for k in req_headers.keys()]:
        req_headers["x-api-key"] = api_key

    # 4. Chuẩn bị payload data
    data_bytes = None
    if payload is not None:
        if isinstance(payload, (dict, list)):
            data_bytes = json.dumps(payload).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(payload, str):
            data_bytes = payload.encode("utf-8")
        elif isinstance(payload, bytes):
            data_bytes = payload

    start_time = time.time()
    response_body = ""
    response_headers = {}
    status_code = 0
    truncated = False

    # 5. Thực thi HTTP request có Stream & Timeout protection
    session = requests.Session()
    try:
        req_kwargs = {
            "method": method_upper,
            "url": target_url,
            "headers": req_headers,
            "timeout": timeout,
            "stream": True,
        }
        if data_bytes is not None:
            req_kwargs["data"] = data_bytes

        resp = session.request(**req_kwargs)
        status_code = resp.status_code
        response_headers = dict(resp.headers)

        # Đọc dữ liệu giới hạn tối đa 2048 bytes
        received_bytes = bytearray()
        for chunk in resp.iter_content(chunk_size=512):
            if chunk:
                received_bytes.extend(chunk)
                if len(received_bytes) >= MAX_RESPONSE_BYTES:
                    truncated = True
                    break

        # Giải mã văn bản an toàn
        response_body = received_bytes[:MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")

    except requests.exceptions.Timeout:
        status_code = 504
        response_body = json.dumps({"status": "error", "message": f"Gateway timeout after {timeout}s"})
    except requests.exceptions.ConnectionError as conn_err:
        status_code = 502
        response_body = json.dumps({"status": "error", "message": f"Connection to Gateway failed: {conn_err}"})
    except requests.exceptions.RequestException as req_err:
        status_code = 500
        response_body = json.dumps({"status": "error", "message": f"Request exception: {req_err}"})
    finally:
        session.close()

    duration_ms = (time.time() - start_time) * 1000.0
    endpoint_path = target_url.replace(DEFAULT_GATEWAY_HOST, "")

    # 6. Ghi vết Audit Log (tự động mask secret + trạng thái phê duyệt)
    log_kwargs = {
        "endpoint": endpoint_path,
        "method": method_upper,
        "status_code": status_code,
        "request_headers": req_headers,
        "response_headers": response_headers,
        "response_body_snippet": response_body,
        "duration_ms": duration_ms,
        "approval_status": approval_status
    }
    if log_file:
        log_kwargs["log_file"] = log_file

    log_audit_event(**log_kwargs)

    # 7. Trả về kết quả đã được làm sạch (masked) cho caller
    return {
        "status": "success" if status_code < 400 else "error",
        "status_code": status_code,
        "endpoint": endpoint_path,
        "method": method_upper,
        "headers": mask_sensitive_data(response_headers),
        "body": mask_sensitive_data(response_body),
        "truncated": truncated,
        "duration_ms": round(duration_ms, 2)
    }


def burst_test(
    url: str,
    count: int = 1,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[Any] = None,
    approval_status: Optional[str] = None
) -> Dict[str, Any]:
    """Gửi liên tiếp N request để kiểm thử giới hạn tốc độ (Rate Limit).

    Inputs:
        url (str): Endpoint cần thử.
        count (int): Số lượng request cần gửi.
        method (str): Phương thức HTTP.
        headers, payload: Các tham số truyền tương ứng.
        approval_status (str, optional): Trạng thái phê duyệt HITL.

    Outputs:
        dict: Bảng tóm tắt kết quả (Tổng số đã gửi, phân bố mã trạng thái HTTP, chi tiết).
    """
    status_counts = {}
    responses = []

    for _ in range(count):
        res = send_request(url, method=method, headers=headers, payload=payload, approval_status=approval_status)
        code = res.get("status_code", 0)
        status_counts[code] = status_counts.get(code, 0) + 1
        responses.append(res)

    return {
        "total_sent": count,
        "status_counts": status_counts,
        "responses": responses
    }


def main():
    """Hàm CLI Runner cho phép người dùng tự điền tham số kiểm thử từ terminal."""
    parser = argparse.ArgumentParser(description="Sentinel Core Python Tool - HTTP Safe Requester")
    parser.add_argument("--url", type=str, default="/api/Quantitys", help="Target endpoint path")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method (GET, POST, OPTIONS)")
    parser.add_argument("--headers", type=str, default=None, help="JSON string of additional headers")
    parser.add_argument("--data", type=str, default=None, help="Raw payload data (for CLI user)")
    parser.add_argument("--count", type=int, default=1, help="Number of consecutive requests to send (burst test)")
    parser.add_argument("--auto-approve", action="store_true", help="Auto approve risky requests without interactive prompt")

    args = parser.parse_args()

    parsed_headers = None
    if args.headers:
        try:
            parsed_headers = json.loads(args.headers)
        except Exception as e:
            print(f"[CLI ERROR] Invalid JSON string in --headers: {e}")
            sys.exit(1)

    parsed_payload = args.data
    if args.data and isinstance(args.data, str):
        try:
            parsed_payload = resolve_safe_payload(args.data)
        except Exception:
            parsed_payload = args.data

    # Đánh giá rủi ro HITL
    risk_assessment = assess_request_risk(args.method, args.url, "custom" if args.data else "long_string", count=args.count)
    if risk_assessment["requires_approval"]:
        approved = prompt_cli_approval(risk_assessment, auto_approve=args.auto_approve)
        if not approved:
            print("[INFO] Action was canceled by user.")
            sys.exit(0)
        approval_status = "APPROVED"
    else:
        approval_status = None

    print(f"\n[+] Executing {args.method} request to '{args.url}' (Count: {args.count})...")
    if args.count > 1:
        summary = burst_test(args.url, count=args.count, method=args.method, headers=parsed_headers, payload=parsed_payload, approval_status=approval_status)
        print(f"[✔] Burst Test Summary: Sent {summary['total_sent']} requests.")
        print(f"    Status Codes Distribution: {json.dumps(summary['status_counts'])}")
    else:
        result = send_request(args.url, method=args.method, headers=parsed_headers, payload=parsed_payload)
        print(f"[✔] Status Code: {result['status_code']}")
        print(f"[✔] Duration: {result['duration_ms']} ms | Truncated: {result['truncated']}")
        print(f"[✔] Response Body (Masked):\n{result['body']}")


if __name__ == "__main__":
    main()
