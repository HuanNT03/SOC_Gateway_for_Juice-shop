# Báo Cáo Tuần 4 - Kong API Gateway

## 1. Sơ Đồ Kiến Trúc Hạ Tầng Kong API Gateway & Network Isolation

```mermaid
flowchart TD
    Client["External Clients / AI Agent / Tester"] -->|"Port 8000"| KongProxy["Kong Proxy"]
    Admin["DevSecOps Admin"] -->|"Port 8001"| KongAdmin["Kong Admin API"]
    
    subgraph IsolatedNetwork["Kong Gateway & Zero Trust Security Enforcement"]
        KongProxy --> GlobalSecurity{"Global Payload Size Control<br>(1MB Max Limit)"}
        
        GlobalSecurity -->|"Exceeded Limit"| Resp413["413 Payload Too Large"]
        GlobalSecurity -->|"Pass"| PreFunction{"Service Pre-Function<br>Zero Trust Policy"}

        PreFunction -->|"x-api-key Present & Invalid Key"| Resp401["401 Unauthorized"]
        PreFunction -->|"x-api-key Present & Disallowed Endpoint"| Resp403["403 Forbidden"]
        PreFunction -->|"x-api-key Present & Allowed Endpoint"| RouteAgent["Route 1: agent-route<br>(Headers: x-api-key ~.+)"]
        PreFunction -->|"No x-api-key Header"| Router{"Route Evaluation & Matching"}

        RouteAgent --> AgentAuth{"Key-Auth & ACL Enforcement<br>(allow: agent-group)"}
        AgentAuth -->|"Pass (Rate Limit 20/min)"| JuiceShop
        
        Router -->|"No Route Matched"| Resp404["404 Not Found"]
        
        Router --> RouteGuest["Route 2: guest-route<br>(Rate Limit: 60/min)"]
        Router --> RouteRegister["Route 3: guest-register-route<br>(POST-only, Rate Limit: 20/min)"]
        Router --> RouteUser["Route 4: user-route<br>(Headers: Bearer JWT, Rate Limit 100/min)"]
        Router --> RouteStatic["Route 5: static-route<br>(Catch-all SPA Assets)"]
        
        RouteGuest --> JuiceShop
        RouteRegister --> JuiceShop
        RouteUser --> JuiceShop
        RouteStatic --> JuiceShop
    end
    
    JuiceShop["OWASP Juice Shop<br>(web:3000 - Internal Network Only)"]
```

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
    Note over Kong: Pre-Function xác thực Key hợp lệ -> agent-route -> ACL allow agent-group
    Kong->>Juice: Proxy Request sang Backend (Redacted API Key)
    Juice-->>Kong: HTTP 200 OK (Data)
    Kong-->>Agent: HTTP 200 OK (Data - Rate Limit: 20/min)

    Note over Agent, Kong: Kịch bản 2: AI Agent dùng API Key cố tình truy cập Route khác (Vượt quyền)
    Agent->>Kong: GET /rest/admin/application-version (Header: x-api-key: agent-secure-key-2026)
    Note over Kong: Pre-Function phát hiện Key hợp lệ nhưng Endpoint ngoài phạm vi được phép
    Kong-->>Agent: HTTP 403 Forbidden ("You cannot consume this service")

    Note over Agent, Kong: Kịch bản 3: Attacker truyền SAI API Key
    Agent->>Kong: GET /api/Quantitys (Header: x-api-key: fake-invalid-key)
    Note over Kong: Pre-Function phát hiện API Key không khớp KONG_VAULT_ENV_AGENT_API_KEY
    Kong-->>Agent: HTTP 401 Unauthorized ("Invalid authentication credentials")

    Note over Client, Juice: Kịch bản 4: Khách / User truy cập trang Web công khai
    Client->>Kong: GET /rest/admin/application-version (No API Key)
    Note over Kong: Pre-Function bỏ qua (No Key) -> Khớp guest-route -> Cho phép truy cập
    Kong->>Juice: Proxy Request sang Backend
    Juice-->>Kong: HTTP 200 OK (Data / Application Version)
    Kong-->>Client: HTTP 200 OK (Data - Rate Limit: 60/min)
```

---

## 3. Nội Dung Báo Cáo Tóm Tắt & Quy Trình Triển Khai

### A. Quản Lý Secret & Biến Môi Trường (Không Hardcode Secret)
- Secret `KONG_VAULT_ENV_AGENT_API_KEY` được khai báo độc lập trong tệp `.env` (`agent-secure-key-2026`).
- Khi container `sentinel-kong-gateway` khởi chạy, câu lệnh `command` trong `docker-compose.yml` thực thi thay thế biến môi trường động vào `/tmp/kong.yml` mà không lưu secret thô trong Git repository.

### B. Cơ Chế Chặn Zero Trust (Pre-Function Policy)
- **Kiểm soát API Key**: Nếu request chứa header `x-api-key` hoặc `apikey`, plugin `pre-function` ở cấp Service lập tức kiểm tra tính hợp lệ. Nếu key không khớp secret môi trường, Gateway từ chối ngay với **`401 Unauthorized`**.
- **Phân quyền Endpoint (RBAC)**: Nếu Key hợp lệ, `pre-function` tiếp tục đối chiếu URI request với danh sách endpoint cho phép (`/api/Quantitys`, `/rest/products/search`, `/rest/user/login`). Nếu truy cập endpoint khác, Gateway từ chối ngay với **`403 Forbidden`**.
- **Tính cô lập cho Guest**: Nếu request không có header `x-api-key`, hệ thống phục vụ người dùng khách vãng lai bình thường qua các route tương ứng (**`200 OK`**).
