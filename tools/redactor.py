"""
Project Sentinel - DevSecOps & AI Gateway
Module: Redactor Engine (tools/redactor.py)

Mục đích:
    Cung cấp cơ chế lọc và che giấu tự động các thông tin nhạy cảm:
    - API Keys, JWT Tokens, Passwords, Session Cookies, Emails.
    - Số điện thoại di động Việt Nam và quốc tế (Phone numbers).
    - Thông tin định danh cá nhân PII (Số CCCD 12 số, CMND 9 số).
    - Số thẻ thanh toán quốc tế (Credit Card / PAN).
    - Chuỗi gán mật khẩu & secret nội dòng (Inline credentials & Connection strings).
    - Khử khuẩn dữ liệu trước khi gửi sang LLM Cloud API (OpenAI/Qwen) và trước khi ghi log Audit.

Đầu vào (Inputs):
    data (dict | list | str | Any): Dữ liệu bất kỳ cần làm sạch (Dict lồng nhau, List, hoặc Chuỗi văn bản).

Đầu ra (Outputs):
    Any: Cấu trúc dữ liệu đã được làm sạch với các thông tin nhạy cảm được thay thế bằng nhãn [REDACTED_*].

Xử lý Edge Cases:
    - Dict/List lồng nhau nhiều tầng (Nested JSON): Sử dụng thuật toán đệ quy (Recursive Processing).
    - Không phân biệt chữ hoa/thường cho các Headers/Key tên trường.
    - Token và secret nội dòng trong chuỗi tự do (VD: password=abc, db://user:pass@host).
    - Thứ tự ưu tiên Regex: Authorization Bearer -> JWT -> Credit Card -> PII -> Phone -> Email -> Inline Secret.
"""

import re
import copy
from typing import Any, List, Dict

# Danh sách từ khóa tên trường / Header được coi là nhạy cảm (Case-insensitive)
SENSITIVE_KEYS = {
    "x-api-key",
    "apikey",
    "authorization",
    "password",
    "token",
    "secret",
    "set-cookie",
    "cookie",
}

# 1. Pattern Regex nhận diện Header Authorization Bearer JWT
BEARER_JWT_REGEX = re.compile(r'Bearer\s+[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b', re.IGNORECASE)

# 2. Pattern Regex nhận diện JWT Token (3 đoạn base64url phân tách bởi dấu chấm)
JWT_REGEX = re.compile(r'\b[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b')

# 3. Pattern Regex nhận diện Thẻ thanh toán quốc tế (Visa, Mastercard, AMEX - 13 đến 19 chữ số hoặc dạng nhóm 4 số)
CREDIT_CARD_REGEX = re.compile(
    r'\b(?:\d{4}[-\s]){3}\d{4}\b|'
    r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|6(?:011|5\d{2})\d{12}|3[47]\d{13}|35\d{14})\b'
)

# 4. Pattern Regex nhận diện Thông tin định danh cá nhân PII (Số CCCD 12 số hoặc CMND 9 số)
PII_REGEX = re.compile(r'\b\d{12}\b|\b\d{9}\b')

# 5. Pattern Regex nhận diện Số điện thoại (VN Mobile 10 số đầu 03/05/07/08/09, Quốc tế +84/Global, Landline)
PHONE_REGEX = re.compile(
    r'(?:\+84(?:[\s.-]?\d){9}\b)|'
    r'(?:\b0[35789](?:[\s.-]?\d){8}\b)|'
    r'(?:\(\d{2,4}\)[\s.-]?\d{3,4}[\s.-]?\d{4}\b)|'
    r'(?:\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b)'
)

# 6. Pattern Regex nhận diện Email
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# 7. Pattern Regex nhận diện Mật khẩu & Token gán trực tiếp trong văn bản (key=value)
INLINE_SECRET_REGEX = re.compile(
    r'(?i)\b(password|passwd|pass|token|secret|api[_-]?key|client[_-]?secret)\s*([:=])\s*([\'"][^\'"\r\n]+[\'"]|[^\s,;&\}\]]+)'
)

# 8. Pattern Regex nhận diện URI Connection String chứa user:password
URI_CREDENTIAL_REGEX = re.compile(
    r'(?i)\b([a-z][a-z0-9+.-]*://)([^:@\s]+):([^@\s]+)@'
)


def _mask_string(text: str) -> str:
    """Hàm phụ trợ: Quét và làm sạch toàn diện các pattern nhạy cảm trong chuỗi văn bản tự do.

    Inputs:
        text (str): Chuỗi đầu vào cần quét.

    Outputs:
        str: Chuỗi đã được ẩn thông tin JWT, Credit Card, PII, SĐT, Email, và Secret nội dòng.
    """
    if not isinstance(text, str):
        return text

    # 1. Che Authorization Bearer JWT trước
    text = BEARER_JWT_REGEX.sub("Bearer [REDACTED_JWT]", text)
    
    # 2. Che JWT thuần 3 đoạn
    text = JWT_REGEX.sub("[REDACTED_JWT]", text)
    
    # 3. Che URI Connection String (VD: postgres://user:pass@host)
    text = URI_CREDENTIAL_REGEX.sub(r'\1\2:[REDACTED_PASSWORD]@', text)

    # 4. Che Inline key=value secrets (VD: password=abc, api_key=xyz)
    def _replace_inline_secret(match: re.Match) -> str:
        key_name = match.group(1)
        separator = match.group(2)
        lower_key = key_name.lower()
        if "pass" in lower_key:
            return f"{key_name}{separator}[REDACTED_PASSWORD]"
        elif "token" in lower_key:
            return f"{key_name}{separator}[REDACTED_TOKEN]"
        else:
            return f"{key_name}{separator}[REDACTED_SECRET]"

    text = INLINE_SECRET_REGEX.sub(_replace_inline_secret, text)

    # 5. Che Thẻ tín dụng
    text = CREDIT_CARD_REGEX.sub("[REDACTED_CREDIT_CARD]", text)

    # 6. Che Số điện thoại
    text = PHONE_REGEX.sub("[REDACTED_PHONE]", text)

    # 7. Che PII (CCCD/CMND)
    text = PII_REGEX.sub("[REDACTED_PII]", text)

    # 8. Che Email
    text = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)

    return text


def mask_sensitive_data(data: Any) -> Any:
    """Hàm đệ quy quét và che giấu các thông tin nhạy cảm trong cấu trúc dữ liệu linh hoạt.

    Inputs:
        data (Any): Dữ liệu đầu vào (dict, list, str, int, float, bool, None).

    Outputs:
        Any: Dữ liệu sao chép an toàn đã được thay thế các secret bằng nhãn [REDACTED_*].
    """
    if data is None:
        return None

    # Xử lý Dictionary (bao gồm Headers & JSON objects)
    if isinstance(data, dict):
        masked_dict = {}
        for key, value in data.items():
            key_str = str(key).strip().lower()
            if key_str in SENSITIVE_KEYS:
                # Nếu là header Authorization Bearer, giữ lại tiền tố Bearer và che token
                if key_str == "authorization" and isinstance(value, str) and "bearer" in value.lower():
                    masked_dict[key] = BEARER_JWT_REGEX.sub("Bearer [REDACTED_JWT]", value)
                else:
                    # Các key nhạy cảm khác (x-api-key, password, set-cookie, v.v.) luôn ghi đè thành [REDACTED_SECRET]
                    masked_dict[key] = "[REDACTED_SECRET]"
            else:
                # Gọi đệ quy cho các trường không thuộc danh sách key nhạy cảm
                masked_dict[key] = mask_sensitive_data(value)
        return masked_dict

    # Xử lý List / Tuple
    if isinstance(data, (list, tuple)):
        return [mask_sensitive_data(item) for item in data]

    # Xử lý String
    if isinstance(data, str):
        return _mask_string(data)

    # Các kiểu dữ liệu nguyên thủy giữ nguyên (int, float, bool)
    return data


def sanitize_llm_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Làm sạch và khử khuẩn 100% ngữ cảnh hội thoại trước khi gửi sang LLM Provider.

    Inputs:
        messages (list[dict]): Danh sách tin nhắn theo định dạng OpenAI format
                               (gồm role, content, tool_calls, v.v.).

    Outputs:
        list[dict]: Danh sách tin nhắn đã được làm sạch mọi dữ liệu nhạy cảm PII và Secret.
    """
    if not isinstance(messages, list):
        return messages

    sanitized_messages = []
    for msg in messages:
        if not isinstance(msg, dict):
            sanitized_messages.append(mask_sensitive_data(msg))
            continue

        clean_msg = copy.deepcopy(msg)
        for field in ["content", "tool_calls", "function_call"]:
            if field in clean_msg and clean_msg[field] is not None:
                clean_msg[field] = mask_sensitive_data(clean_msg[field])

        sanitized_messages.append(clean_msg)

    return sanitized_messages


def main():
    """Hàm CLI Runner cho phép người dùng nhập văn bản để kiểm tra khử khuẩn PII."""
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel Core - PII & Sensitive Data Redactor CLI")
    parser.add_argument("--text", type=str, default=None, help="Chuỗi văn bản cần khử khuẩn")
    args = parser.parse_args()

    input_text = args.text
    if not input_text:
        print("\n" + "=" * 70)
        print("🛡️  [PROJECT SENTINEL] PII & SENSITIVE DATA REDACTOR CLI")
        print("=" * 70)
        try:
            input_text = input("👉 Nhập văn bản cần kiểm tra khử khuẩn PII: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[INFO] Đã hủy.")
            return

    if not input_text:
        input_text = "Khách hàng 0912-345-678, Visa 4532-0150-9988-1234, email admin@juiceshop.local, pass secretPass123"

    masked_output = mask_sensitive_data(input_text)
    print("\n" + "=" * 70)
    print("📋 [KẾT QUẢ ĐỐI SOÁT KHỬ KHUẨN PII]")
    print("=" * 70)
    print("[1] VĂN BẢN ĐẦU VÀO (RAW INPUT):")
    print(f"    {input_text}")
    print("-" * 70)
    print("[2] VĂN BẢN ĐÃ LÀM SẠCH (SANITIZED OUTPUT):")
    print(f"    {masked_output}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
