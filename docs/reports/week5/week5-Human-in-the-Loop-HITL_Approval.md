# Báo Cáo Kỹ Thuật Tuần 5: Cơ Chế Phê Duyệt Thủ Công (Human-in-the-Loop - HITL Approval) (Plan 8)

**Dự án**: Project Sentinel - DevSecOps & AI Gateway  
**Mục tiêu**: Xây dựng cơ chế chốt chặn an toàn có sự tham gia của con người (Human-in-the-Loop - HITL) bắt buộc phải có sự xác nhận (`Approve` hoặc `Reject`) trước khi thực thi bất kỳ request nào có khả năng gây rủi ro cao (phương thức POST/PUT/DELETE, payload đặc biệt, payload ngoại cỡ > 1MB, burst test lưu lượng lớn).

---

## 🎯 1. Tóm Tắt Kết Quả Triển Khai (Executive Summary)

Trong Plan 8, AI Security Agent đã được trang bị **Động cơ Đánh giá Rủi ro (Risk Assessment Engine)** và **Cơ chế Chốt chặn Phê duyệt Tương tác (Interactive HITL Approval Gate)**:

```
[Agent Đề Xuất Kịch Bản] (VD: POST /api/Quantitys, Oversized Payload 1.5MB, Burst Test)
           │
           ▼
[assess_request_risk(method, url, category, count)]
           │
           ├──> LOW RISK (Ví dụ: GET endpoint thông thường trong allowlist):
           │    └──> Tự động thực thi an toàn qua Kong Gateway.
           │
           └──> MEDIUM / HIGH RISK (POST, Payload > 1MB, Injection, Burst Traffic):
                └──> ⚠️ Kích hoạt Hộp thoại Phê duyệt (HITL Prompt)
                     │
                     ├──> Người dùng chọn "y" (Approve):
                     │    ├──> Tiếp tục gửi request qua Kong API Gateway.
                     │    └──> Ghi log Audit với nhãn: approval_status: "APPROVED".
                     │
                     └──> Người dùng chọn "n" / Enter / Timeout (Reject - Fail Closed):
                          ├──> 🛑 HỦY BỎ NGAY LẬP TỨC. Tuyệt đối KHÔNG gửi gói tin qua mạng.
                          ├──> Trả về kết quả status: "rejected" và status_code: 0.
                          └──> Ghi log Audit với nhãn: approval_status: "REJECTED_BY_USER".
```

---

## 🛡️ 2. Các Thành Phần Kỹ Thuật Đã Xây Dựng

### 2.1. Động Cơ Phân Loại Rủi Ro Request (`assess_request_risk` trong `tools/safe_requester.py`)
- Phân tích đa tiêu chí để đánh giá mức độ rủi ro trước khi thực thi:
  1. **Phương thức HTTP**: Các phương thức thay đổi trạng thái dữ liệu (`POST`, `PUT`, `DELETE`, `PATCH`) ➔ `MEDIUM` Risk.
  2. **Dung lượng & Phân loại Payload**:
     - `oversized_payload` (Dữ liệu ~1.5MB) ➔ `HIGH` Risk (Nguy cơ nghẽn RAM / Băng thông).
     - `special_chars`, `query_param_injection` ➔ `MEDIUM` Risk (Thăm dò lỗ hổng).
  3. **Lưu lượng Burst Test**: `count > 10` requests liên tiếp ➔ `HIGH` Risk (Nguy cơ DoS / Rate Limit).
- Trả về cấu trúc chi tiết: `requires_approval` (bool), `risk_level` ("LOW" | "MEDIUM" | "HIGH"), `risk_factors` (danh sách lý do), `purpose` (mục đích kiểm thử).

---

### 2.2. Hộp Thoại Tương Tác Dòng Lệnh (`prompt_cli_approval` trong `tools/safe_requester.py`)
- Khi phát hiện hành động rủi ro, hệ thống hiển thị bảng cảnh báo trực quan trên CLI:
  ```text
  ======================================================================
  ⚠️  [HUMAN-IN-THE-LOOP] YÊU CẦU PHÊ DUYỆT HÀNH ĐỘNG RỦI RO
  ======================================================================
  - Mục tiêu kiểm thử:   POST /api/Quantitys
  - Nhóm Payload:        oversized_payload
  - Số lượng request:    1
  - Mục đích kiểm tra:   Kiểm chứng Gateway chặn 413 Payload Too Large khi nhận dữ liệu ngoại cỡ > 1MB
  - Mức độ rủi ro:       HIGH
  - Các yếu tố rủi ro:
     • Phương thức HTTP 'POST' có khả năng tạo/thay đổi trạng thái dữ liệu trên server
     • Payload ngoại cỡ (oversized_payload ~1.5MB) có thể gây áp lực băng thông và tài nguyên bộ nhớ Gateway
  ----------------------------------------------------------------------
  👉 Bạn có CHẤP THUẬN gửi request này không? (y/N): 
  ```
- **Nguyên tắc Fail-Closed (Mặc định từ chối)**: Bấm Enter (chuỗi rỗng), nhập ký tự lạ hoặc ngắt tín hiệu (`KeyboardInterrupt`/`EOFError`) đều tự động coi là `Reject`.
- **Hỗ trợ Headless / CI/CD**: Hỗ trợ cờ `--auto-approve` và biến môi trường `CI_MODE=true`, `AUTO_APPROVE=true` để chạy tự động hóa trong pipeline CI mà không bị treo tiến trình.

---

### 2.3. Tích Hợp Chốt Chặn Vào Agent (`agent/agent.py`)
- Hàm `execute_proposal()` tự động gọi `assess_request_risk()` và `prompt_cli_approval()`.
- Khi người dùng từ chối (`Reject`):
  - Agent dừng hoàn toàn mọi thao tác gửi request qua mạng.
  - Ghi vết kiểm toán an toàn với nhãn `approval_status: "REJECTED_BY_USER"`.
  - Hàm `format_agent_report()` xuất thông báo an ninh: `🛑 HÀNH ĐỘNG ĐÃ BỊ HỦY BỎ BỞI NGƯỜI DÙNG (HUMAN-IN-THE-LOOP REJECTION)`.

---

## 🧪 3. Kết Quả Kiểm Thử Tự Động (Test Suite Results)

Bộ kiểm thử `tests/test_human_approval.py` và toàn bộ test suite của dự án đạt **100% Pass** trong thời gian tối ưu:

| File Kiểm Thử | Số lượng Test Cases | Trạng Thái | Thời Gian |
|---|:---:|:---:|:---:|
| `tests/test_human_approval.py` | 6 | ✅ PASS (100%) | 0.003s |
| `tests/test_prompt_injection.py` | 6 | ✅ PASS (100%) | 0.002s |
| `tests/test_advanced_redactor.py` | 5 | ✅ PASS (100%) | 0.001s |
| `tests/test_agent.py` | 6 | ✅ PASS (100%) | 0.002s |
| `tests/test_logger.py` | 1 | ✅ PASS (100%) | 0.001s |
| `tests/test_payload_handler.py` | 5 | ✅ PASS (100%) | 0.001s |
| `tests/test_redactor.py` | 4 | ✅ PASS (100%) | 0.001s |
| `tests/test_safe_requester.py` | 4 | ✅ PASS (100%) | 0.005s |
| `tests/test_ui.py` | 2 | ✅ PASS (100%) | 0.003s |
| **TỔNG CỘNG** | **39 Test Cases** | **✅ ALL PASS** | **0.017s** |

---

## 📁 4. Danh Mục Tệp Tin Đã Tạo & Cập Nhật

- `tools/safe_requester.py`: Bổ sung `assess_request_risk()`, `prompt_cli_approval()`, và cờ `--auto-approve`.
- `tools/logger.py`: Bổ sung trường `approval_status` vào hàm `log_audit_event()`.
- `agent/agent.py`: Tích hợp chốt chặn HITL vào luồng thực thi `execute_proposal()` và báo cáo `format_agent_report()`.
- `tests/test_human_approval.py`: Bộ 6 test cases kiểm thử độc lập cho HITL.
- `plans/plan8_human_in_the_loop_approval.md`: Đánh dấu hoàn thành toàn bộ checklist nhiệm vụ.
- `plans/README.md`: Cập nhật trạng thái tổng thể của Plan 8.
