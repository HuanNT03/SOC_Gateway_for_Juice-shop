# Báo Cáo Tuần 4 - Kong API Gateway

## 1. Sơ Đồ Kiến Trúc Hạ Tầng Kong API Gateway & Network Isolation

```mermaid
flowchart TD
    ClientExt["External Client / AI Agent / Attacker"]
    AdminExt["DevSecOps Admin"]

    AdminExt -->|"Admin API (Port 8001)"| KongAdmin["Kong Admin API"]
    
    ClientExt -->|"Proxy Access (Port 8000)"| KongProxy["Kong API Gateway Proxy"]
    ClientExt -.->|"Direct Access Port 3000 (Blocked)"| DirectBlock["❌ Blocked / Restricted<br>(Direct Upstream Access Forbidden)"]

    subgraph SentinelNet["Isolated Docker Bridge Network (sentinel-net)"]
        KongProxy --> Router{"Route Evaluation & Matching"}

        Router -->|"No Route Matched"| Resp404["404 Not Found"]
        
        Router --> RouteGuest["Route 1: guest-route<br>(Public Endpoints, Rate Limit: 60/min)"]
        Router --> RouteRegister["Route 2: guest-register-route<br>(POST-only, Rate Limit: 20/min)"]
        Router --> RouteUser["Route 3: user-route<br>(Headers: Bearer JWT, Rate Limit: 100/min)"]
        Router --> RouteStatic["Route 4: static-route<br>(Catch-all SPA Assets)"]

        RouteGuest --> ServicePipeline
        RouteRegister --> ServicePipeline
        RouteUser --> ServicePipeline
        RouteStatic --> ServicePipeline

        subgraph ServicePipeline["Service-Level Enforcement Pipeline (juice-shop-service)"]
            PayloadControl{"Global Payload Size Control<br>(1MB Max Limit)"}
            PayloadControl -->|"Exceeded Limit"| Resp413["413 Payload Too Large"]
            PayloadControl -->|"Pass"| PreFunction{"Service Pre-Function<br>Zero Trust Policy"}

            PreFunction -->|"x-api-key Present & Invalid Key"| Resp401["401 Unauthorized"]
            PreFunction -->|"x-api-key Present & Disallowed Endpoint"| Resp403["403 Forbidden"]
            PreFunction -->|"Pass"| KeyAuth{"Key-Auth Plugin<br>(anonymous: anonymous-user)"}

            KeyAuth -->|"Valid x-api-key"| ConsAgent["Consumer: ai-agent"]
            KeyAuth -->|"No x-api-key"| ConsGuest["Consumer: anonymous-user"]

            ConsAgent --> ACL{"Service ACL Enforcement<br>(allow: agent-group, guest-group)"}
            ConsGuest --> ACL

            ACL --> RateEval{"Consumer-Scoped Rate Limiting"}
            RateEval -->|"Consumer: ai-agent"| LimitAgent["Consumer Override Rate Limit: 20/min"]
            RateEval -->|"Consumer: anonymous-user"| LimitGuest["Fallback to Route Rate Limit (e.g. 60/min)"]
        end

        LimitAgent --> JuiceShop
        LimitGuest --> JuiceShop
        
        JuiceShop["OWASP Juice Shop Backend<br>(web:3000 - Internal Service Only)"]
    end
```

> **Lưu ý về Nguyên tắc Cô lập Mạng (Network Isolation)**:
> - **Cổng 8000 (Kong Proxy)** là điểm đầu vào duy nhất (**Single Entrypoint**) cho mọi lưu lượng từ bên ngoài.
> - **Cổng 3000 (Juice Shop)** nằm trong mạng nội bộ `sentinel-net`. Trong mô hình sản xuất DevSecOps, các yêu cầu truy cập trực tiếp cổng 3000 (không qua Gateway 8000) đều bị chặn để đảm bảo mọi request phải qua bộ lọc Zero Trust.

---

## 2. Luồng Hoạt Động Kiến Trúc Decoupled JWT & Zero Trust RBAC

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Security Agent / Attacker
    actor Client as Guest / User Client
    participant Kong as Kong Gateway (Port 8000)
    participant Juice as Juice Shop (Backend web:3000)

    Note over Agent, Kong: Kịch bản 1: AI Agent dùng API Key hợp lệ gọi Endpoint được phép
    Agent->>Kong: GET /api/Quantitys (Header: x-api-key: agent-secure-key-2026)
    Note over Kong: Router match guest-route -> Service Pre-Function hợp lệ -> Key-Auth identify consumer ai-agent -> Consumer Rate-Limit 20/min
    Kong->>Juice: Proxy Request sang Backend (Redacted API Key)
    Juice-->>Kong: HTTP 200 OK (Data)
    Kong-->>Agent: HTTP 200 OK (Data - Rate Limit: 20/min)

    Note over Agent, Kong: Kịch bản 2: AI Agent dùng API Key cố tình truy cập Route ngoài Scope (Vượt quyền)
    Agent->>Kong: GET /rest/admin/application-version (Header: x-api-key: agent-secure-key-2026)
    Note over Kong: Router match guest-route -> Service Pre-Function phát hiện Key hợp lệ nhưng Endpoint ngoài phạm vi cho phép
    Kong-->>Agent: HTTP 403 Forbidden ("You cannot consume this service")

    Note over Agent, Kong: Kịch bản 3: Attacker truyền SAI API Key
    Agent->>Kong: GET /api/Quantitys (Header: x-api-key: fake-invalid-key)
    Note over Kong: Service Pre-Function phát hiện API Key không khớp secret môi trường
    Kong-->>Agent: HTTP 401 Unauthorized ("Invalid authentication credentials")

    Note over Client, Juice: Kịch bản 4: Khách / User truy cập trang Web công khai
    Client->>Kong: GET /rest/admin/application-version (No API Key)
    Note over Kong: Pre-Function bỏ qua (No Key) -> Key-Auth gán anonymous-user -> Áp dụng Rate Limit của guest-route (60/min)
    Kong->>Juice: Proxy Request sang Backend
    Juice-->>Kong: HTTP 200 OK (Data / Application Version)
    Kong-->>Client: HTTP 200 OK (Data - Rate Limit: 60/min)
```

---

## 3. Nội Dung Báo Cáo Tóm Tắt & Quy Trình Triển Khai

### A. Quản Lý Secret & Biến Môi Trường (Không Hardcode Secret)
- Secret `KONG_VAULT_ENV_AGENT_API_KEY` được khai báo độc lập trong tệp `.env` (`agent-secure-key-2026`).
- Khi container `sentinel-kong-gateway` khởi chạy, câu lệnh `command` trong `docker-compose.yml` thực thi thay thế biến môi trường động vào `/tmp/kong.yml` mà không lưu secret thô trong Git repository.

### B. Cơ Chế Chặn Zero Trust & Consumer-Scoped Rate Limiting (Option B Architecture)
- **Kiểm soát API Key**: Nếu request chứa header `x-api-key` hoặc `apikey`, plugin `pre-function` ở cấp Service lập tức kiểm tra tính hợp lệ. Nếu key không khớp secret môi trường, Gateway từ chối ngay với **`401 Unauthorized`**.
- **Phân quyền Endpoint (RBAC Scope)**: Nếu Key hợp lệ, `pre-function` tiếp tục đối chiếu URI request với danh sách endpoint cho phép (`/api/Quantitys`, `/rest/products/search`, `/rest/user/login`). Nếu truy cập endpoint khác (ví dụ `/rest/admin/application-version`), Gateway từ chối ngay với **`403 Forbidden`**.
- **Xác thực Consumer & Tránh Shadowing Route**: Sử dụng `key-auth` ở cấp Service với cấu hình `anonymous: anonymous-user`. Điều này giúp định danh chính xác Consumer `ai-agent` khi có API key hợp lệ, và tự động chuyển về `anonymous-user` khi không có key mà không gặp lỗi shadowing route trong thuật toán routing traditional của Kong.
- **Giới hạn Tốc độ Dựa trên Consumer Identity**: Áp dụng plugin `rate-limiting` cho consumer `ai-agent` ở mức 20 requests/phút. Người dùng công khai (guest) không truyền API Key sẽ tuân theo rate limit mặc định của từng route (60 requests/phút đối với public endpoints và 20 requests/phút đối với registration anti-spam).
