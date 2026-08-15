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
| `make up` | `make up` | Khởi chạy toàn bộ hạ tầng (Juice Shop + Kong Gateway). |
| `make down` | `make down` | Dừng và gỡ bỏ các container hạ tầng. |
| `make restart` | `make restart` | Khởi động lại toàn bộ các dịch vụ. |
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

