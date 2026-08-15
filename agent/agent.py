"""
Project Sentinel - DevSecOps & AI Gateway
Module: AI Security Analysis Agent (agent/agent.py)

Mục đích:
    Nhận yêu cầu kiểm thử bằng ngôn ngữ tự nhiên từ người dùng, phân tích kịch bản,
    đọc config/payloads.json để đề xuất các tham số kiểm thử an toàn, gọi safe_requester.py
    thực thi request qua Kong Gateway và tổng hợp báo cáo an ninh theo System Prompt & Mindset Guardrails.

Đầu vào (Inputs):
    user_prompt (str): Lệnh kiểm thử bằng văn bản tự do của người dùng.

Đầu ra (Outputs):
    dict: Kết quả đề xuất, phản hồi HTTP và báo cáo đánh giá an ninh.

Xử lý Edge Cases:
    - Nhận diện các mã 413, 429, 403 là "GATEWAY HOẠT ĐỘNG ĐÚNG THIẾT KẾ" (không coi là thất bại).
    - Giới hạn payload chọn từ config/payloads.json, không tự sinh payload phá hoại.
"""

import sys
import os
import json
from typing import Any, Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.safe_requester import send_request, burst_test, resolve_safe_payload, load_payloads_dict


def analyze_user_request(user_prompt: str) -> str:
    """Phân tích văn bản yêu cầu của người dùng để xác định kịch bản kiểm thử phù hợp.

    Inputs:
        user_prompt (str): Câu lệnh từ người dùng.

    Outputs:
        str: Mã kịch bản ("rate_limit", "forbidden_endpoint", "oversized_payload", "special_chars", "general_check").
    """
    if not user_prompt or not isinstance(user_prompt, str):
        return "general_check"

    prompt_lower = user_prompt.lower().strip()

    if any(k in prompt_lower for k in ["rate limit", "tốc độ", "burst", "nhiều request", "429"]):
        return "rate_limit"
    if any(k in prompt_lower for k in ["admin", "forbidden", "bị cấm", "không được phép", "403"]):
        return "forbidden_endpoint"
    if any(k in prompt_lower for k in ["oversized", "1.5mb", "lớn", "file to", "quá to", "413"]):
        return "oversized_payload"
    if any(k in prompt_lower for k in ["xss", "special", "ký tự", "injection", "đặc biệt"]):
        return "special_chars"

    return "general_check"


def generate_proposal(scenario_key: str) -> Dict[str, Any]:
    """Đọc config/payloads.json và tạo đề xuất kịch bản kiểm thử chi tiết.

    Inputs:
        scenario_key (str): Mã kịch bản đã phân tích.

    Outputs:
        dict: Đề xuất kịch bản bao gồm url, method, payload_category, payload_value, count và giải thích.
    """
    payloads = load_payloads_dict()

    if scenario_key == "rate_limit":
        return {
            "scenario_name": "Kiểm thử giới hạn tốc độ (Rate Limiting Test)",
            "url": "/api/Quantitys",
            "method": "GET",
            "count": 25,
            "payload_category": "long_string",
            "payload_value": None,
            "explanation": "Gửi liên tiếp 25 request tới /api/Quantitys để kiểm chứng plugin rate-limiting (ngưỡng 20 req/min)."
        }

    if scenario_key == "forbidden_endpoint":
        return {
            "scenario_name": "Kiểm thử Endpoint bị cấm (ACL Allowlist Test)",
            "url": "/rest/admin/application-version",
            "method": "GET",
            "count": 1,
            "payload_category": "long_string",
            "payload_value": None,
            "explanation": "Gửi request tới /rest/admin/application-version nằm ngoài allowlist để kiểm chứng trả về 403 Forbidden."
        }

    if scenario_key == "oversized_payload":
        return {
            "scenario_name": "Kiểm thử Payload ngoại cỡ > 1MB (Request Size Limiting Test)",
            "url": "/api/Quantitys",
            "method": "POST",
            "count": 1,
            "payload_category": "oversized_payload",
            "payload_value": None,
            "explanation": "Yêu cầu Tool tự sinh chuỗi 1.5MB trong RAM để kiểm chứng plugin request-size-limiting trả về 413 Payload Too Large."
        }

    if scenario_key == "special_chars":
        approved_specials = payloads.get("special_chars", ["' \" < > & ; --"])
        chosen_val = approved_specials[1] if len(approved_specials) > 1 else approved_specials[0]
        return {
            "scenario_name": "Kiểm thử ký tự đặc biệt (Special Chars / Injection Probe Test)",
            "url": "/rest/products/search",
            "method": "GET",
            "count": 1,
            "payload_category": "special_chars",
            "payload_value": chosen_val,
            "explanation": f"Gửi ký tự đặc biệt an toàn '{chosen_val}' qua query string để kiểm thử phản ứng filter của Gateway."
        }

    # Default general check
    return {
        "scenario_name": "Kiểm thử kết nối API hợp lệ (Valid Allowlist Endpoint Test)",
        "url": "/api/Quantitys",
        "method": "GET",
        "count": 1,
        "payload_category": "long_string",
        "payload_value": None,
        "explanation": "Gửi 1 request GET hợp lệ tới /api/Quantitys nằm trong allowlist."
    }


def execute_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Thực thi đề xuất thông qua safe_requester.py.

    Inputs:
        proposal (dict): Đề xuất kịch bản từ generate_proposal().

    Outputs:
        dict: Kết quả thực thi từ Tool.
    """
    url = proposal.get("url", "/api/Quantitys")
    method = proposal.get("method", "GET")
    count = proposal.get("count", 1)
    category = proposal.get("payload_category", "long_string")
    value = proposal.get("payload_value", None)

    # Tra cứu safe payload
    try:
        resolved_payload = resolve_safe_payload(category, value)
    except Exception as err:
        return {"status": "error", "status_code": 400, "message": f"Payload resolution failed: {err}"}

    if count > 1:
        return burst_test(url, count=count, method=method, payload=resolved_payload)

    return send_request(url, method=method, payload=resolved_payload)


def format_agent_report(result: Dict[str, Any]) -> str:
    """Tổng hợp báo cáo đánh giá an ninh theo Mindset Guardrails cho người dùng.

    Inputs:
        result (dict): Kết quả thực thi từ execute_proposal().

    Outputs:
        str: Văn bản báo cáo an ninh hoàn chỉnh.
    """
    # Nếu là kết quả burst test
    if "total_sent" in result:
        total = result["total_sent"]
        counts = result.get("status_counts", {})
        report_lines = [
            f"📊 **BÁO CÁO BURST RATE LIMIT TEST**",
            f"- **Tổng request đã gửi**: {total}",
            f"- **Phân bố Mã Trạng Thái HTTP**: {json.dumps(counts)}",
        ]
        if counts.get(429, 0) > 0:
            report_lines.append("🛡️ **ĐÁNH GIÁ AN NINH**: **GATEWAY HOẠT ĐỘNG ĐÚNG THIẾT KẾ (429 Too Many Requests)**.")
            report_lines.append("   Plugin `rate-limiting` đã kích hoạt chặn thành công các request vượt ngưỡng lưu lượng.")
        else:
            report_lines.append("ℹ️ **ĐÁNH GIÁ AN NINH**: Lưu lượng chưa vượt ngưỡng chặn Rate Limit.")
        return "\n".join(report_lines)

    code = result.get("status_code", 0)
    endpoint = result.get("endpoint", "")
    duration = result.get("duration_ms", 0)
    body = result.get("body", "")

    lines = [
        f"🛡️ **BÁO CÁO ĐÁNH GIÁ AN NINH API GATEWAY**",
        f"- **Endpoint**: `{endpoint}`",
        f"- **Mã phản hồi HTTP**: `{code}`",
        f"- **Thời gian xử lý**: `{duration} ms`",
        ""
    ]

    if code == 200:
        lines.append("✅ **ĐÁNH GIÁ**: Request được chấp nhận (200 OK). Backend Juice Shop phản hồi dữ liệu bình thường.")
    elif code == 401:
        lines.append("⚠️ **ĐÁNH GIÁ**: Gateway từ chối request (401 Unauthorized). API Key bị thiếu hoặc không hợp lệ.")
    elif code == 403:
        lines.append("🛡️ **ĐÁNH GIÁ**: **GATEWAY HOẠT ĐỘNG ĐÚNG THIẾT KẾ (403 Forbidden)**.")
        lines.append("   Chính sách ACL / Allowlist đã ngăn chặn thành công endpoint ngoài phạm vi cho phép.")
    elif code == 413:
        lines.append("🛡️ **ĐÁNH GIÁ**: **GATEWAY HOẠT ĐỘNG ĐÚNG THIẾT KẾ (413 Payload Too Large)**.")
        lines.append("   Plugin `request-size-limiting` đã ngăn chặn thành công payload ngoại cỡ > 1MB.")
    elif code == 429:
        lines.append("🛡️ **ĐÁNH GIÁ**: **GATEWAY HOẠT ĐỘNG ĐÚNG THIẾT KẾ (429 Too Many Requests)**.")
        lines.append("   Plugin `rate-limiting` đã ngăn chặn thành công tần suất truy cập vượt ngưỡng cho phép.")
    elif code == 405:
        lines.append("🛡️ **ĐÁNH GIÁ**: **TOOL POLICY HOẠT ĐỘNG ĐÚNG THIẾT KẾ (405 Method Not Allowed)**.")
        lines.append("   Phương thức HTTP bị từ chối theo chính sách kiểm thử an toàn.")
    else:
        lines.append(f"ℹ️ **ĐÁNH GIÁ**: Mã phản hồi `{code}` thu được từ Gateway/Backend.")

    lines.append(f"\n**Response Body Snippet (Masked)**:\n```\n{str(body)[:500]}\n```")
    return "\n".join(lines)


def run_agent_session(user_prompt: str) -> str:
    """Luồng xử lý hoàn chỉnh một phiên làm việc của Agent khi nhận lệnh từ Người dùng."""
    scenario_key = analyze_user_request(user_prompt)
    proposal = generate_proposal(scenario_key)

    print(f"\n🤖 [AGENT THINKING] Phân tích yêu cầu: '{user_prompt}' -> Kịch bản: '{proposal['scenario_name']}'")
    print(f"💡 [AGENT PROPOSAL] {proposal['explanation']}")
    print(f"   Target: {proposal['method']} {proposal['url']} | Payload Category: {proposal['payload_category']}")

    result = execute_proposal(proposal)
    report = format_agent_report(result)
    return report


if __name__ == "__main__":
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Kiểm tra rate limit của endpoint /api/Quantitys"
    final_report = run_agent_session(prompt)
    print("\n" + final_report)
