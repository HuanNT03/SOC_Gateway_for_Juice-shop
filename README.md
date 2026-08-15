# Project Sentinel - DevSecOps & Kong API Gateway (Week 4)

Dự án triển khai lớp bảo vệ Kong API Gateway đứng trước ứng dụng OWASP Juice Shop, tích hợp bộ kiểm thử HTTP an toàn (Python Core Tool) phục vụ AI Security Agent và DevSecOps Audit.

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

2. **Cài đặt thư viện Python cần thiết**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Khởi chạy hạ tầng Kong Gateway & Juice Shop**:
   ```bash
   make up
   ```
   - **Kong Proxy Access**: [http://localhost:8000](http://localhost:8000)
   - **Kong Admin API**: [http://localhost:8001](http://localhost:8001) *(Cổng nội bộ)*

4. **Kiểm tra trạng thái dịch vụ**:
   ```bash
   make status
   ```

---

## 🛠️ 2. Danh Sách Lệnh Makefile Khả Dụng

| Lệnh | Cú pháp sử dụng | Mô tả chức năng |
|---|---|---|
| `make help` | `make help` | Hiển thị menu hướng dẫn các lệnh trong Makefile. |
| `make up` | `make up` | Khởi chạy toàn bộ hạ tầng (Juice Shop + Kong Gateway + Streamlit Agent UI). |
| `make down` | `make down` | Dừng và gỡ bỏ toàn bộ container. |
| `make restart` | `make restart` | Khởi động lại toàn bộ các dịch vụ. |
| `make server-up` | `make server-up` | Khởi chạy riêng dịch vụ máy chủ Backend (Kong Gateway + Juice Shop). |
| `make server-down` | `make server-down` | Dừng riêng dịch vụ máy chủ Backend (Kong Gateway + Juice Shop). |
| `make server-restart` | `make server-restart` | Khởi động lại riêng dịch vụ máy chủ Backend. |
| `make server-logs` | `make server-logs` | Xem nhật ký (logs) thời gian thực của máy chủ Backend. |
| `make ui-logs` | `make ui-logs` | Xem nhật ký (logs) thời gian thực của container Streamlit Agent UI. |
| `make status` | `make status` | Kiểm tra trạng thái và Health Check của các container. |
| `make logs` | `make logs` | Xem nhật ký (logs) thời gian thực của toàn bộ hệ thống. |
| `make routes` | `make routes` | Truy vấn danh sách Routes đang nạp trong Kong Admin API (Port 8001). |
| `make test-request` | `make test-request URL=/api/Quantitys METHOD=GET` | Gửi 1 HTTP request an toàn qua Kong Gateway. |
| `make test-ratelimit` | `make test-ratelimit COUNT=25` | Chạy burst test N request kiểm chứng Rate Limit (429). |
| `make clean` | `make clean` | Dọn dẹp hoàn toàn containers, volumes và Docker images. |

---

## 🧪 3. Hướng Dẫn Sử Dụng Core Python Tool (`tools/safe_requester.py`)

Công cụ Python Tool được thiết kế nhằm tự động tiêm `x-api-key` bí mật từ môi trường, áp đặt timeout 7 giây, giải nén `gzip` an toàn và tự động mã hóa bí mật (`mask_sensitive_data`) trước khi ghi log vào `logs/gateway_audit.jsonl`.

### Cú pháp chạy trực tiếp bằng Python:

```bash
python3 tools/safe_requester.py --url <ENDPOINT> --method <GET|POST|OPTIONS> [--data '<JSON_PAYLOAD>'] [--count N]
```

### 💡 Các kịch bản tham số mẫu đề xuất:

1. **Kiểm thử Endpoint hợp lệ trong Allowlist (200 OK)**:
   ```bash
   make test-request URL=/api/Quantitys METHOD=GET
   ```

2. **Kiểm thử Endpoint ngoài phạm vi Allowlist (403 Forbidden)**:
   ```bash
   make test-request URL=/rest/admin/application-version METHOD=GET
   ```

3. **Kiểm thử Phương thức HTTP bị cấm theo Policy (405 Method Not Allowed)**:
   ```bash
   make test-request URL=/api/Quantitys METHOD=DELETE
   ```

4. **Kiểm thử Giới hạn tốc độ Burst Rate Limit (429 Too Many Requests)**:
   ```bash
   make test-ratelimit URL=/api/Quantitys COUNT=25
   ```

5. **Kiểm thử Payload ngoại cỡ > 1MB (413 Payload Too Large)**:
   ```bash
   make test-request URL=/api/Quantitys METHOD=POST DATA=oversized_payload
   ```
   > **Lưu ý**: Phải sử dụng phương thức **`METHOD=POST`** (hoặc PUT) để tải Request Body lên kết nối. Phương thức `GET` không upload body nên Gateway sẽ trả về 200 OK bình thường.

---

## 🛡️ 4. Thư Viện Safe Payloads & Guardrails (`config/payloads.json`)

Hệ thống cung cấp danh sách các nhóm payload kiểm thử an toàn (benign test payloads) được lưu tại `config/payloads.json`:

- **`long_string`**: Kiểm thử xử lý chuỗi ký tự dài an toàn.
- **`special_chars`**: Kiểm thử bộ lọc ký tự HTML/SQL benign (`' " < > & ; --`).
- **`empty_values`**: Kiểm thử giá trị rỗng (`""`, `null`, `{}`).
- **`type_mismatch`**: Kiểm thử sai kiểu dữ liệu trường dữ liệu.
- **`query_param_injection`**: Kiểm thử đường truyền query string (`' OR 1=1`, `<img src=x>`).
- **`oversized_payload`**: Kích hoạt kịch bản thử payload 1.5MB do Tool tự sinh trong RAM (chặn `413 Payload Too Large`).

### System Prompt Guardrails (`agent/system_prompt.txt`):
- Chống Prompt Injection từ HTTP Response body.
- **Mindset Guardrails**: Định hướng AI Agent coi các mã **`413`**, **`429`**, **`403`** là **thành công của hệ thống phòng thủ**, không tự ý retry.

---

---

## 🤖 5. Hướng Dẫn Cấu Hình & Sử Dụng Real AI Security Agent (`agent/agent.py`)

AI Security Agent là một **Agent thực sự** được tích hợp thư viện `openai` SDK (tương thích với **Alibaba Cloud DashScope / Qwen API** hoặc OpenAI). Agent có khả năng phân tích câu lệnh tự nhiên, thực hiện **Tool Calling (Function Calling)** để gọi `tools/safe_requester.py` và tổng hợp báo cáo an ninh theo Mindset Guardrails.

### 🔑 Cấu Hình Biến Môi Trường (`.env`):

Khai báo các tham số API Key và Endpoint trong tệp `.env` (xem mẫu tại `.env.example`):

```env
# AI Security Agent LLM Configuration (OpenAI SDK / Alibaba Cloud Qwen API)
AI_AGENT_API_KEY=your_alibaba_or_openai_api_key_here
AI_AGENT_BASE_URL=https://dashscope-intl.aliyuncs.com/compatible-mode/v1
AI_AGENT_MODEL=qwen-plus

# Kong Gateway API Key Secret
KONG_VAULT_ENV_AGENT_API_KEY=your_kong_gateway_agent_api_key_here
AGENT_API_KEY=your_kong_gateway_agent_api_key_here
```

> **Lưu ý**: Nếu chưa cấu hình `AI_AGENT_API_KEY` hoặc hết quota, Agent sẽ tự động kích hoạt **Chế độ dự phòng (Rule-based Engine Fallback)** để đảm bảo hệ thống và các bộ kiểm thử tự động (Unit Tests) hoạt động liên tục không bị gián đoạn.

### 🛠️ Khai Báo Tool Specification (`TOOL_SCHEMA`):
Agent sử dụng bảng định nghĩa Tool Schema chuẩn hóa dạng JSON Schema để truyền tham số chính xác vào `safe_requester.py`:
- **Đầu vào (Inputs)**:
  - `url` (str): Path endpoint mục tiêu (VD: `/api/Quantitys`, `/rest/admin/application-version`).
  - `method` (str): Phương thức HTTP (`GET`, `POST`, `OPTIONS`).
  - `payload_category` (str): Nhóm payload an toàn (`long_string`, `special_chars`, `empty_values`, `type_mismatch`, `query_param_injection`, `oversized_payload`).
  - `payload_value` (str, optional): Giá trị cụ thể chọn trong nhóm.
  - `count` (int, optional): Số lượng request burst rate limit (VD: `25`).
- **Đầu ra (Outputs)**: Dictionary gồm `status_code`, `endpoint`, `method`, `headers` (masked), `body` (masked, max 2KB), `truncated`, `duration_ms`.

### Cú pháp chạy trực tiếp từ Terminal:

```bash
python3 agent/agent.py "<CÂU_LỆNH_KIỂM_THỬ>"
```

### 💡 Các ví dụ lệnh mẫu:

1. **Kiểm thử Rate Limit**:
   ```bash
   python3 agent/agent.py "Hãy kiểm tra rate limit của endpoint /api/Quantitys"
   ```

2. **Kiểm thử Endpoint bị cấm (403 Forbidden)**:
   ```bash
   python3 agent/agent.py "Thử truy cập vào endpoint admin /rest/admin/application-version"
   ```

3. **Kiểm thử Payload ngoại cỡ (413 Payload Too Large)**:
   ```bash
   python3 agent/agent.py "Gửi file lớn hoặc oversized payload để test gateway"
   ```

4. **Kiểm thử Ký tự đặc biệt (XSS/Injection Probe)**:
   ```bash
   python3 agent/agent.py "Thử chèn ký tự đặc biệt vào search endpoint"
   ```

---

## 🖥️ 6. Giao Diện Web UI (Streamlit Dashboard)

Giao diện trực quan dựa trên Streamlit cho phép người dùng điều khiển Trợ lý AI Security Agent, thực hiện các kịch bản test thủ công và soi nhật ký Audit Log thời gian thực.

### Cú pháp khởi chạy:

```bash
streamlit run agent/ui.py
```
Sau khi chạy, ứng dụng tự động mở giao diện tại địa chỉ: `http://localhost:8501`.

---

## 🧪 7. Kiểm Thử Độc Lập Unit Test Suite

Toàn bộ các test case được đặt tập trung tại thư mục `tests/`:

```bash
python3 -m unittest discover -s tests
```



