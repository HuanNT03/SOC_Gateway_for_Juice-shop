"""
Project Sentinel - DevSecOps & AI Gateway
Module: Real AI Security Analysis Agent (agent/agent.py)

Mục đích:
    Xây dựng AI Security Agent thực sự sử dụng OpenAI SDK (tương thích với Alibaba Cloud Qwen / DashScope API).
    - Nạp cấu hình API Key và Endpoint linh hoạt từ môi trường (`.env`).
    - Sử dụng mô hình LLM để hiểu câu lệnh tự nhiên của người dùng và thực hiện Tool Calling (Function Calling).
    - Hoạt động dựa trên System Prompt & Mindset Guardrails (chống Prompt Injection, nhận diện 413/429/403 là thành công của Gateway).
    - Tự động chuyển sang chế độ dự phòng (Rule-based Fallback) khi không có API Key để đảm bảo tính sẵn sàng và chạy test offline.

Đầu vào (Inputs):
    user_prompt (str): Yêu cầu kiểm thử bằng ngôn ngữ tự nhiên.

Đầu ra (Outputs):
    dict/str: Kịch bản đề xuất, kết quả thực thi và báo cáo đánh giá an ninh.
"""

import sys
import os
import json
from typing import Any, Dict, Optional
from dotenv import load_dotenv

# Nạp các biến môi trường từ tệp .env
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from tools.safe_requester import send_request, burst_test, resolve_safe_payload, load_payloads_dict, TOOL_SCHEMA

# Đọc cấu hình LLM từ môi trường
AI_AGENT_API_KEY = os.getenv("AI_AGENT_API_KEY", "").strip()
AI_AGENT_BASE_URL = os.getenv("AI_AGENT_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1").strip()
AI_AGENT_MODEL = os.getenv("AI_AGENT_MODEL", "qwen-plus").strip()

SYSTEM_PROMPT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "system_prompt.txt"))

def _load_system_prompt() -> str:
    """Tải nội dung System Prompt và Guardrails từ tệp system_prompt.txt."""
    if os.path.exists(SYSTEM_PROMPT_PATH):
        try:
            with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            pass
    return "Bạn là AI Security Agent chuyên kiểm thử an ninh API Gateway."


def analyze_user_request(user_prompt: str) -> str:
    """Phân tích văn bản yêu cầu để xác định kịch bản kiểm thử (Hỗ trợ LLM & Rule-based fallback)."""
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


import re

LAST_FALLBACK_REASON = ""

def generate_proposal_llm(user_prompt: str) -> Optional[Dict[str, Any]]:
    """Sử dụng OpenAI SDK (tương thích Alibaba Cloud Qwen API) để phân tích câu lệnh và đề xuất Tool Calling."""
    global LAST_FALLBACK_REASON
    LAST_FALLBACK_REASON = ""

    if not AI_AGENT_API_KEY:
        LAST_FALLBACK_REASON = "AI_AGENT_API_KEY chưa được khai báo trong tệp .env"
        return None

    try:
        from openai import OpenAI
        client = OpenAI(
            api_key=AI_AGENT_API_KEY,
            base_url=AI_AGENT_BASE_URL
        )

        system_prompt = _load_system_prompt()
        payloads_summary = json.dumps(load_payloads_dict(), ensure_ascii=False)

        messages = [
            {"role": "system", "content": f"{system_prompt}\n\nDanh sách Payloads an toàn khả dụng:\n{payloads_summary}"},
            {"role": "user", "content": f"Hãy đề xuất kịch bản kiểm thử cho yêu cầu sau: {user_prompt}"}
        ]

        tools_spec = [
            {
                "type": "function",
                "function": TOOL_SCHEMA
            }
        ]

        response = client.chat.completions.create(
            model=AI_AGENT_MODEL,
            messages=messages,
            tools=tools_spec,
            tool_choice="auto",
            temperature=0.1
        )

        message = response.choices[0].message
        if message.tool_calls:
            tool_call = message.tool_calls[0]
            args = json.loads(tool_call.function.arguments)
            
            url = args.get("url", "/api/Quantitys")
            method = args.get("method", "GET")
            category = args.get("payload_category", "long_string")
            value = args.get("payload_value", None)

            # Ưu tiên lấy count từ LLM Tool Call argument
            llm_count = args.get("count")
            if llm_count and isinstance(llm_count, int) and llm_count > 0:
                count = llm_count
            else:
                # Tìm số lượng request trong câu lệnh của người dùng (VD: 30 request -> 30)
                match = re.search(r"(\d+)\s*(?:req|request|lần)?", user_prompt.lower())
                if match and int(match.group(1)) > 1:
                    count = int(match.group(1))
                else:
                    count = 25 if "rate" in user_prompt.lower() or category == "rate_limit" else 1

            return {
                "scenario_name": f"LLM Proposed: {category} on {method} {url}",
                "url": url,
                "method": method,
                "count": count,
                "payload_category": category,
                "payload_value": value,
                "explanation": f"LLM ({AI_AGENT_MODEL}) phân tích yêu cầu và đề xuất gọi Tool '{tool_call.function.name}' (Category: '{category}', Count: {count}).",
                "used_llm": True,
                "model": AI_AGENT_MODEL
            }
    except Exception as err:
        LAST_FALLBACK_REASON = f"Lỗi gọi LLM API ({err})"
        print(f"[LLM WARNING] Falling back to rule-based engine due to LLM call issue: {err}")
    
    return None


def generate_proposal(scenario_key_or_prompt: str) -> Dict[str, Any]:
    """Tạo đề xuất kịch bản kiểm thử chi tiết. Ưu tiên LLM, tự động fallback về Rule-based."""
    global LAST_FALLBACK_REASON

    # Thử gọi LLM nếu câu lệnh là chuỗi ngữ cảnh dài
    if AI_AGENT_API_KEY:
        llm_proposal = generate_proposal_llm(scenario_key_or_prompt)
        if llm_proposal:
            return llm_proposal
    else:
        LAST_FALLBACK_REASON = "AI_AGENT_API_KEY chưa được khai báo trong .env"

    # Fallback Rule-based Engine
    scenario_key = analyze_user_request(scenario_key_or_prompt)
    payloads = load_payloads_dict()

    # Trích xuất số lượng count trong prompt nếu người dùng yêu cầu cụ thể (VD: 30 request)
    match_count = re.search(r"(\d+)\s*(?:req|request|lần)?", scenario_key_or_prompt.lower())
    parsed_count = int(match_count.group(1)) if match_count and int(match_count.group(1)) > 1 else 25

    if scenario_key == "rate_limit":
        return {
            "scenario_name": "Kiểm thử giới hạn tốc độ (Rate Limiting Test)",
            "url": "/api/Quantitys",
            "method": "GET",
            "count": parsed_count,
            "payload_category": "long_string",
            "payload_value": None,
            "explanation": f"Gửi liên tiếp {parsed_count} request tới /api/Quantitys để kiểm chứng plugin rate-limiting (ngưỡng 20 req/min).",
            "used_llm": False,
            "fallback_reason": LAST_FALLBACK_REASON
        }

    if scenario_key == "forbidden_endpoint":
        return {
            "scenario_name": "Kiểm thử Endpoint bị cấm (ACL Allowlist Test)",
            "url": "/rest/admin/application-version",
            "method": "GET",
            "count": 1,
            "payload_category": "long_string",
            "payload_value": None,
            "explanation": "Gửi request tới /rest/admin/application-version nằm ngoài allowlist để kiểm chứng trả về 403 Forbidden.",
            "used_llm": False,
            "fallback_reason": LAST_FALLBACK_REASON
        }

    if scenario_key == "oversized_payload":
        return {
            "scenario_name": "Kiểm thử Payload ngoại cỡ > 1MB (Request Size Limiting Test)",
            "url": "/api/Quantitys",
            "method": "POST",
            "count": 1,
            "payload_category": "oversized_payload",
            "payload_value": None,
            "explanation": "Yêu cầu Tool tự sinh chuỗi 1.5MB trong RAM để kiểm chứng plugin request-size-limiting trả về 413 Payload Too Large.",
            "used_llm": False,
            "fallback_reason": LAST_FALLBACK_REASON
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
            "explanation": f"Gửi ký tự đặc biệt an toàn '{chosen_val}' qua query string để kiểm thử phản ứng filter của Gateway.",
            "used_llm": False,
            "fallback_reason": LAST_FALLBACK_REASON
        }

    return {
        "scenario_name": "Kiểm thử kết nối API hợp lệ (Valid Allowlist Endpoint Test)",
        "url": "/api/Quantitys",
        "method": "GET",
        "count": 1,
        "payload_category": "long_string",
        "payload_value": None,
        "explanation": "Gửi 1 request GET hợp lệ tới /api/Quantitys nằm trong allowlist.",
        "used_llm": False,
        "fallback_reason": LAST_FALLBACK_REASON
    }


def execute_proposal(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Thực thi đề xuất thông qua safe_requester.py."""
    url = proposal.get("url", "/api/Quantitys")
    method = proposal.get("method", "GET")
    count = proposal.get("count", 1)
    category = proposal.get("payload_category", "long_string")
    value = proposal.get("payload_value", None)

    try:
        resolved_payload = resolve_safe_payload(category, value)
    except Exception as err:
        return {"status": "error", "status_code": 400, "message": f"Payload resolution failed: {err}"}

    if count > 1:
        return burst_test(url, count=count, method=method, payload=resolved_payload)

    return send_request(url, method=method, payload=resolved_payload)


def format_agent_report(result: Dict[str, Any]) -> str:
    """Tổng hợp báo cáo đánh giá an ninh theo Mindset Guardrails cho người dùng."""
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
    proposal = generate_proposal(user_prompt)

    engine_tag = f"LLM ({proposal.get('model', AI_AGENT_MODEL)})" if proposal.get("used_llm") else "Rule-based Engine Fallback"
    print(f"\n🤖 [AGENT THINKING - {engine_tag}] Phân tích yêu cầu: '{user_prompt}'")
    if not proposal.get("used_llm"):
        raw_err = proposal.get("fallback_reason") or "AI_AGENT_API_KEY chưa được khai báo trong .env"
        print(f"⚠️ [LLM FALLBACK REASON] {raw_err}")
    print(f"💡 [AGENT PROPOSAL] {proposal['explanation']}")
    print(f"   Target: {proposal['method']} {proposal['url']} | Payload Category: {proposal['payload_category']}")

    result = execute_proposal(proposal)
    report = format_agent_report(result)
    return report


if __name__ == "__main__":
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Kiểm tra rate limit của endpoint /api/Quantitys"
    final_report = run_agent_session(prompt)
    print("\n" + final_report)
