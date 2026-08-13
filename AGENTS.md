# Quyền Hạn & Quy Chuẩn Thư Mục Dự Án (Project Sentinel - Week 4)

## 1. Giải Thích Ý Nghĩa Thư Mục (Folder Overview)

- **`gateway/`**: Chứa tệp cấu hình khai báo (declarative configuration) và quy tắc định tuyến cho **Kong API Gateway**.
- **`tools/`**: Chứa mã nguồn công cụ Python (`safe_requester.py`) hỗ trợ gửi request kiểm thử an toàn qua API Gateway.
- **`agent/`**: Quản lý System Prompt (`system_prompt.txt`) và logic phân tích lỗ hổng của AI Security Analysis Agent.
- **`logs/`**: Lưu trữ nhật ký (audit logs) truy vấn request/response và tự động che bỏ thông tin nhạy cảm trước khi ghi tệp.
- **`config/`**: Lưu trữ các tệp cấu hình hệ thống bao gồm danh sách endpoint hợp lệ (`allowlist.json`).
- **`docs/`**: Lưu trữ tài liệu hướng dẫn dự án và các báo cáo kết quả quét bảo mật đầu ra (`docs/reports/`).

---

## 2. Quy Chuẩn Thực Thi Bắt Buộc (Mandatory Execution Rules)

1. **Chia Nhỏ Task & Git Commit**:
   - Mọi yêu cầu phát triển hoặc chỉnh sửa hệ thống phải luôn được chia nhỏ thành các task nhỏ (atomic tasks) để thực thi từng bước.
   - Phải thực hiện commit vào Git ngay sau khi hoàn thành mỗi task nhỏ để đảm bảo quản lý lịch sử mã nguồn rõ ràng.

2. **Giải Thích Code & Chức Năng Hàm Chi Tiết**:
   - Tất cả mã nguồn được viết phải kèm chú thích (docstring/comments) đầy đủ và rõ ràng.
   - Phải giải thích chi tiết: mục đích mã nguồn, ý nghĩa và chức năng của từng hàm, định nghĩa các tham số đầu vào (inputs) và giá trị trả về đầu ra (outputs).
