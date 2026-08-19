# Project Sentinel - DevSecOps, AI Security Agent & API Gateway (Week 5)

Dự án triển khai lớp bảo vệ **Kong API Gateway (v3.6)** đứng trước ứng dụng **OWASP Juice Shop (v20.1.1)**, tích hợp **AI Security Agent (Qwen)**, **Bộ khiên phòng vệ Prompt Injection 2 chiều**, **Bộ khử khuẩn dữ liệu PII/Secrets**, **Chốt chặn phê duyệt Human-in-the-Loop (HITL)** và **Giao diện Web UI Dashboard 4 Tabs** phục vụ DevSecOps & Security Audit.

---

## 🚀 1. Hướng Dẫn Khởi Chạy Nhanh (Quickstart)

### Yêu cầu tiên quyết:
- Docker & Docker Compose v2+
- Python 3.10+
- GNU Make

### Các bước thực hiện:

1. **Khởi tạo tệp cấu hình môi trường**:
   ```bash
   cp .env.example .env
   ```

2. **Cài đặt thư viện Python**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Khởi chạy toàn bộ hạ tầng (Juice Shop + Kong Gateway + Agent UI)**:
   ```bash
   make up
   ```
   - **Kong Proxy Gateway**: [http://localhost:8000](http://localhost:8000)
   - **Kong Admin API**: [http://localhost:8001](http://localhost:8001) *(Cổng nội bộ)*
   - **Streamlit Web UI Dashboard**: [http://localhost:8501](http://localhost:8501)

4. **Kiểm tra trạng thái dịch vụ**:
   ```bash
   make status
   ```

---

## 🛠️ 2. Danh Sách Lệnh Makefile Khả Dụng

| Nhóm Lệnh | Cú pháp | Mô tả chức năng |
|---|---|---|
| **Hạ tầng Docker** | `make up` | Khởi chạy toàn bộ hạ tầng (Juice Shop + Kong Gateway + Streamlit UI). |
| | `make down` | Dừng và gỡ bỏ toàn bộ containers. |
| | `make restart` | Khởi động lại toàn bộ dịch vụ. |
| | `make status` | Kiểm tra trạng thái và Health Check của các container. |
| | `make logs` | Xem nhật ký thời gian thực toàn hệ thống. |
| | `make clean` | Dọn dẹp hoàn toàn containers, volumes và Docker images. |
| **Kiểm thử Tuần 5** | `make test-week5` | Chạy toàn bộ **40 unit test cases** tự động (Redaction + Injection + HITL + UI). |
| | `make test-redaction` | Kiểm tra khử khuẩn văn bản nhập từ bàn phím (hỗ trợ cả `TEXT="..."`). |
| | `make test-live-injection` | Chạy kịch bản E2E Live Prompt Injection + PII Probe với Real LLM Model (Qwen). |
| | `make agent-interactive` | Khởi chạy CLI Agent ở chế độ tương tác hỏi phê duyệt HITL trực tiếp trên Terminal. |
| **Kiểm thử HTTP Gateway** | `make test-request` | Gửi 1 HTTP request qua Gateway (`make test-request URL=/api/Quantitys METHOD=GET`). |
| | `make test-ratelimit` | Chạy burst test N request kiểm chứng Rate Limit 429 (`make test-ratelimit COUNT=25`). |
| **Trợ giúp** | `make help` | Hiển thị menu hướng dẫn các lệnh trong Makefile. |

---

## 🛡️ 3. Các Trụ Cột An Ninh Cốt Lõi (Week 5 Architecture)

### 3.1. Advanced PII & Data Redaction (`tools/redactor.py`)
- Tự động nhận diện và che giấu 100% thông tin nhạy cảm trước khi ghi tệp log Audit hoặc gửi ra LLM Provider:
  - Số điện thoại Việt Nam & quốc tế ➔ `[REDACTED_PHONE]`
  - Số CCCD/CMND ➔ `[REDACTED_PII]`
  - Số thẻ tín dụng / Visa / Mastercard ➔ `[REDACTED_CREDIT_CARD]`
  - Địa chỉ Email ➔ `[REDACTED_EMAIL]`
  - Mật khẩu nội dòng & Connection String DB ➔ `[REDACTED_PASSWORD]`
  - Bearer JWT Token & Headers nhạy cảm (`x-api-key`, `authorization`, `cookie`) ➔ `[REDACTED_JWT]`, `[REDACTED_SECRET]`

### 3.2. Prompt Injection Defense & AI Guardrails (`agent/guardrails.py`)
- **Phòng thủ 2 chiều (Bidirectional Shield)**:
  - **Lớp 1 (Direct User Input)**: Ngăn chặn câu lệnh tấn công từ người dùng cố ý bẻ khóa vai trò (Jailbreak / DAN mode), ghi đè quy tắc (`ignore previous instructions`), hoặc moi móc API Key/System Prompt. Tự động chặn ngay tại cổng vào và từ chối gọi Tool.
  - **Lớp 2 (Indirect HTTP Response)**: Quét phản hồi từ máy chủ, giương cờ cảnh báo nếu chứa injection độc hại song ngữ (Anh - Việt), và bọc dữ liệu trong thẻ `<untrusted_http_response>` trước khi gửi sang Real LLM.
- **Quy tắc Bất biến (Inviolable Guardrails)** trong `agent/system_prompt.txt`.

### 3.3. Human-in-the-Loop (HITL) Approval Engine (`tools/safe_requester.py`)
- **Động cơ phân loại rủi ro (`assess_request_risk`)**:
  - `LOW`: Phương thức `GET`/`OPTIONS` allowlist, payload lành tính, `count <= 10` ➔ Tự động thực thi an toàn.
  - `MEDIUM`: Phương thức `POST`/`PUT`/`DELETE`, payload thăm dò `special_chars`, hoặc `10 < count <= 20` ➔ Bắt buộc phê duyệt.
  - `HIGH`: Payload ngoại cỡ `oversized_payload` (~1.5MB) hoặc burst test `count > 20` ➔ Bắt buộc phê duyệt cảnh báo tài nguyên.
  - `CRITICAL`: Direct Prompt Injection ➔ Guardrail tự động chặn đứng.
- **Hộp thoại tương tác (`prompt_cli_approval`)**:
  - Khi người dùng chọn `Approve` (`y/Y`): Gửi request qua Gateway, log `approval_status: "APPROVED"`.
  - Khi người dùng chọn `Reject` (`n/N` hoặc Enter): **Hủy bỏ ngay lập tức, 0 network socket**, log `approval_status: "REJECTED_BY_USER"`.
  - Hỗ trợ `--auto-approve`, `CI_MODE=true` cho môi trường CI/CD.

### 3.4. Web UI Dashboard 4 Tabs (`agent/ui.py`)
1. **Tab 1: 🤖 AI Security Agent**: Tương tác tự nhiên, hỗ trợ thẻ HITL Warning Card, Real LLM Dynamic Analysis và Preset Live Injection & PII Probe.
2. **Tab 2: ⚡ Manual HTTP Tester**: Thử nghiệm HTTP request & Burst test thủ công kèm đánh giá rủi ro HITL trước khi phát lệnh.
3. **Tab 3: 📜 Audit Log Inspector**: Giám sát nhật ký Audit Log (`logs/gateway_audit.jsonl`) đã khử khuẩn 100% PII.
4. **Tab 4: 🛡️ Guardrails & Safety Inspector**: Công cụ khử khuẩn PII trực tiếp (Live PII Tester), đối soát lịch sử phê duyệt HITL và System Prompt rules.

---

## 🧪 4. Kiểm Thử Tự Động Toàn Diện (Automated Test Suite)

Dự án sở hữu bộ kiểm thử tự động gồm **40 test cases** bao phủ toàn diện từ Plan 1 đến Plan 9:

```bash
make test-week5
```

**Kết quả kiểm thử**:
```text
Ran 40 tests in 0.020s
OK (100% PASS)
```

---

## 📁 5. Cấu Trúc Thư Mục Dự Án

```
SOC_Gateway_for_Juice-shop/
├── agent/                      # AI Security Agent & Guardrails
│   ├── agent.py                # Core Agent logic, Tool Calling, Real LLM (Qwen) & HITL
│   ├── guardrails.py           # 2-way Prompt Injection scanner & Context Delimiter
│   ├── system_prompt.txt       # System Prompt với Inviolable Guardrail Rules
│   └── ui.py                   # Streamlit Web UI Dashboard (4 Tabs)
├── config/                     # Cấu hình hệ thống & Payloads
│   ├── allowlist.json          # Danh sách endpoint hợp lệ
│   └── payloads.json           # Thư viện Benign Test Payloads
├── docs/                       # Tài liệu dự án & Báo cáo kỹ thuật
│   └── reports/week5/          # Báo cáo kỹ thuật chi tiết các tuần
├── gateway/                    # Cấu hình Kong API Gateway
│   └── kong.yml                # Cấu hình Declarative DB-less cho Kong v3.6
├── logs/                       # Nhật ký kiểm toán an toàn (Audit Logs)
│   └── gateway_audit.jsonl     # Audit log format JSONL đã che 100% Secret & PII
├── tests/                      # Bộ kiểm thử tự động (40 Unit Test Cases)
│   ├── test_advanced_redactor.py # Kiểm thử PII, CCCD, Thẻ tín dụng, DB URI
│   ├── test_human_approval.py  # Kiểm thử HITL Risk Engine & Approve/Reject
│   ├── test_prompt_injection.py# Kiểm thử Prompt Injection song ngữ & XML Delimiters
│   ├── test_ui.py              # Kiểm thử UI Helpers & Badges
│   └── ...
├── tools/                      # Công cụ Python Core
│   ├── logger.py               # Module ghi log audit an toàn
│   ├── redactor.py             # Module khử khuẩn PII & làm sạch LLM messages
│   ├── safe_requester.py       # Core Safe Requester Client & HITL Evaluator
│   └── simulate_injection_probe.py # Kịch bản E2E Live Prompt Injection Probe
├── docker-compose.yml          # Quản lý 3 containers (Kong, Juice Shop, Agent UI)
├── Makefile                    # Hệ thống tự động hóa lệnh CLI
└── requirements.txt            # Danh sách thư viện phụ thuộc Python
```
