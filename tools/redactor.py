"""
Project Sentinel - DevSecOps & AI Gateway
Module: Redactor Engine (tools/redactor.py)

Mục đích:
    Cung cấp cơ chế lọc và che giấu tự động các thông tin nhạy cảm (API Keys, JWT Tokens, Passwords, Session Cookies, Emails)
    từ dữ liệu Request/Response Headers và Body trước khi ghi log Audit hoặc trả về cho Agent/User.

Đầu vào (Inputs):
    data (dict | list | str | Any): Dữ liệu bất kỳ cần làm sạch (Dict lồng nhau, List, hoặc Chuỗi văn bản).

Đầu ra (Outputs):
    Any: Cấu trúc dữ liệu đã được làm sạch với các thông tin nhạy cảm được thay thế bằng nhãn [REDACTED_*].

Xử lý Edge Cases:
    - Dict/List lồng nhau nhiều tầng (Nested JSON): Sử dụng thuật toán đệ quy (Recursive Processing).
    - Không phân biệt chữ hoa/thường cho các Headers/Key tên trường.
    - JWT Token đứng một mình trong chuỗi JSON body (3 đoạn base64url nối bằng dấu .).
"""

import re
import copy
from typing import Any

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

# Pattern Regex nhận diện Email
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Pattern Regex nhận diện JWT Token (3 đoạn base64url phân tách bởi dấu chấm, độ dài tối thiểu 4 ký tự mỗi đoạn)
JWT_REGEX = re.compile(r'\b[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b')

# Pattern Regex nhận diện Header Authorization Bearer JWT
BEARER_JWT_REGEX = re.compile(r'Bearer\s+[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b', re.IGNORECASE)


def _mask_string(text: str) -> str:
    """Hàm phụ trợ: Quét và làm sạch các pattern nhạy cảm trong chuỗi văn bản tự do.

    Inputs:
        text (str): Chuỗi đầu vào cần quét.

    Outputs:
        str: Chuỗi đã được ẩn các thông tin Email và JWT.
    """
    if not isinstance(text, str):
        return text

    # Che Authorization Bearer JWT trước
    text = BEARER_JWT_REGEX.sub("Bearer [REDACTED_JWT]", text)
    # Che JWT thuần 3 đoạn
    text = JWT_REGEX.sub("[REDACTED_JWT]", text)
    # Che Email
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
