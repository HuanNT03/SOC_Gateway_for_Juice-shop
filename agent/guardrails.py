"""
Project Sentinel - DevSecOps & AI Gateway
Module: AI Guardrails & Prompt Injection Defense (agent/guardrails.py)

Mục đích:
    Cung cấp cơ chế phòng thủ đa tầng chống tấn công Prompt Injection:
    - Quét phát hiện tấn công 2 chiều: Direct User Input và Indirect HTTP Response.
    - Hỗ trợ phát hiện song ngữ toàn diện: Tiếng Anh và Tiếng Việt.
    - Nhận diện các kỹ thuật: Instruction Override, Role-play/Jailbreak (DAN), Secret Exfiltration, Unauthorized Commands.
    - Đóng gói dữ liệu không tin cậy vào cặp thẻ phân tách tường minh <untrusted_http_response>.

Đầu vào (Inputs):
    text (str): Chuỗi văn bản từ câu lệnh người dùng hoặc phản hồi HTTP server.
    source (str): Nguồn dữ liệu ("user_input", "http_response", "auto").

Đầu ra (Outputs):
    dict: Kết quả phân tích {is_injection, detected_patterns, risk_level, matched_language, source}.
"""

import re
import html
from typing import Dict, Any, List, Optional

# Danh sách mẫu Prompt Injection Tiếng Anh (Regex compiled)
EN_INJECTION_PATTERNS = [
    # 1. Ghi đè chỉ dẫn (Instruction Override)
    (re.compile(r'\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|system|above)\s+(?:instructions|rules|prompts|directives)\b', re.IGNORECASE), "Instruction Override"),
    (re.compile(r'\b(?:system\s+reset|new\s+instructions?:|new\s+system\s+prompt:)\b', re.IGNORECASE), "System Reset / New Directive"),
    
    # 2. Khai thác vai trò (Jailbreak / DAN Mode)
    (re.compile(r'\b(?:you\s+are\s+(?:now\s+)?in\s+developer\s+mode|act\s+as\s+(?:an\s+)?unrestricted\s+ai|dan\s+mode|jailbroken|unfiltered\s+mode)\b', re.IGNORECASE), "Jailbreak / Role-play"),
    (re.compile(r'\b(?:pretend\s+you\s+have\s+no\s+(?:rules|filters|limitations))\b', re.IGNORECASE), "Bypass Filter Role-play"),

    # 3. Rò rỉ thông tin bí mật (Secret Exfiltration)
    (re.compile(r'\b(?:print|show|reveal|display|output|leak|echo)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:system\s+prompt|api[_-]?key|secret|token|password|env(?:ironment)?\s+variables?|x-api-key)\b', re.IGNORECASE), "Secret Exfiltration Attempt"),
    (re.compile(r'\b(?:what\s+is\s+your\s+(?:system\s+prompt|api[_-]?key|secret\s+key))\b', re.IGNORECASE), "Direct Secret Query"),

    # 4. Tiêm lệnh trái phép (Unauthorized Actions)
    (re.compile(r'\b(?:call\s+tool\s+with|execute\s+drop\s+(?:database|table)|run\s+command\s+|curl\s+https?://)\b', re.IGNORECASE), "Unauthorized Command Injection")
]

# Danh sách mẫu Prompt Injection Tiếng Việt (Regex compiled)
VI_INJECTION_PATTERNS = [
    # 1. Ghi đè chỉ dẫn (Instruction Override)
    (re.compile(r'(?:bỏ\s+qua|quên\s+hết|hủy\s+bỏ|bỏ\s+hết)\s+(?:mọi\s+|tất\s+cả\s+|các\s+|những\s+)?(?:chỉ\s+dẫn|hướng\s+dẫn|quy\s+tắc|yêu\s+cầu|ràng\s+buộc)(?:\s+(?:trước(?:\s+đó)?|cũ|ở\s+trên))?', re.IGNORECASE), "Ghi đè chỉ dẫn (Tiếng Việt)"),
    (re.compile(r'(?:ghi\s+đè\s+system\s+prompt|chỉ\s+dẫn\s+mới\s+của\s+bạn\s+là|thiết\s+lập\s+lại\s+hệ\s+thống)', re.IGNORECASE), "Tái thiết lập hệ thống (Tiếng Việt)"),

    # 2. Khai thác vai trò (Jailbreak / Developer Mode)
    (re.compile(r'(?:chuyển\s+sang\s+chế\s+độ\s+nhà\s+phát\s+triển|đóng\s+vai\s+(?:ai|chatgpt|robot)\s+không\s+giới\s+hạn|chế\s+độ\s+bẻ\s+khóa|không\s+bị\s+kiểm\s+duyệt)', re.IGNORECASE), "Bẻ khóa vai trò (Tiếng Việt)"),
    (re.compile(r'(?:giả\s+vờ\s+như\s+bạn\s+không\s+có\s+(?:quy\s+tắc|bộ\s+lọc|giới\s+hạn))', re.IGNORECASE), "Giả lập bỏ qua quy tắc (Tiếng Việt)"),

    # 3. Rò rỉ thông tin bí mật (Secret Exfiltration)
    (re.compile(r'(?:in|hiển\s+thị|tiết\s+lộ|xuất|cho\s+xem|đọc|nói\s+cho\s+tôi)\s+(?:ra\s+)?(?:toàn\s+bộ\s+)?(?:system\s+prompt|api[_-]?key|khóa\s+bí\s+mật|mật\s+khẩu|biến\s+môi\s+trường|token|khóa\s+api)', re.IGNORECASE), "Moi móc bí mật (Tiếng Việt)"),
    (re.compile(r'(?:system\s+prompt\s+của\s+bạn\s+là\s+gì|api\s+key\s+của\s+bạn\s+là\s+gì)', re.IGNORECASE), "Hỏi thẳng bí mật (Tiếng Việt)"),

    # 4. Tiêm lệnh trái phép (Unauthorized Actions)
    (re.compile(r'(?:gửi\s+request\s+tới\s+url\s+cấm|xóa\s+(?:toàn\s+bộ\s+|hết\s+)?cơ\s+sở\s+dữ\s+liệu|thực\s+thi\s+lệnh\s+xóa)', re.IGNORECASE), "Tiêm lệnh độc hại (Tiếng Việt)")
]


def detect_prompt_injection(text: str, source: str = "auto") -> Dict[str, Any]:
    """Quét và phân tích văn bản để phát hiện các dấu hiệu tấn công Prompt Injection song ngữ (Anh - Việt).

    Inputs:
        text (str): Chuỗi văn bản cần phân tích (User Prompt hoặc Response Body).
        source (str): Nguồn gốc văn bản ("user_input", "http_response", "auto").

    Outputs:
        dict: {
            "is_injection": bool,
            "detected_patterns": list[str],
            "risk_level": "LOW" | "HIGH" | "CRITICAL",
            "matched_language": "en" | "vi" | "both" | "none",
            "source": str
        }
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "is_injection": False,
            "detected_patterns": [],
            "risk_level": "LOW",
            "matched_language": "none",
            "source": source
        }

    detected_patterns: List[str] = []
    has_en = False
    has_vi = False

    # 1. Quét mẫu Tiếng Anh
    for pattern, label in EN_INJECTION_PATTERNS:
        if pattern.search(text):
            detected_patterns.append(f"[EN] {label}")
            has_en = True

    # 2. Quét mẫu Tiếng Việt
    for pattern, label in VI_INJECTION_PATTERNS:
        if pattern.search(text):
            detected_patterns.append(f"[VI] {label}")
            has_vi = True

    is_injection = len(detected_patterns) > 0

    # Xác định ngôn ngữ phát hiện
    matched_language = "none"
    if has_en and has_vi:
        matched_language = "both"
    elif has_en:
        matched_language = "en"
    elif has_vi:
        matched_language = "vi"

    # Đánh giá mức độ rủi ro
    if not is_injection:
        risk_level = "LOW"
    elif len(detected_patterns) >= 2 or any("Secret Exfiltration" in p or "Moi móc bí mật" in p for p in detected_patterns):
        risk_level = "CRITICAL"
    else:
        risk_level = "HIGH"

    return {
        "is_injection": is_injection,
        "detected_patterns": detected_patterns,
        "risk_level": risk_level,
        "matched_language": matched_language,
        "source": source
    }


def sanitize_untrusted_response(raw_body: str) -> str:
    """Đóng gói phản hồi không tin cậy vào thẻ phân tách tường minh <untrusted_http_response>.

    Inputs:
        raw_body (str): Dữ liệu thô từ HTTP response sau khi đã được che giấu PII.

    Outputs:
        str: Chuỗi văn bản an toàn đã được đóng khung trong thẻ phân tách ranh giới ngữ cảnh.
    """
    if not isinstance(raw_body, str):
        raw_body = str(raw_body)

    # Escape các thẻ nhạy cảm có thể gây phá vỡ cấu trúc XML
    safe_body = raw_body.replace("</untrusted_http_response>", "&lt;/untrusted_http_response&gt;")

    return f"<untrusted_http_response>\n{safe_body}\n</untrusted_http_response>"
