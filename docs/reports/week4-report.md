# Báo Cáo Tuần 4 - Kong API Gateway

## 1. Sơ Đồ Kiến Trúc Hạ Tầng Kong API Gateway & Network Isolation

```mermaid
flowchart TD
    ClientExt["External Client / AI Agent / Attacker"]
    AdminExt["DevSecOps Admin"]

    AdminExt -->|"Admin API (Port 8001)"| KongAdmin["Kong Admin API"]
    
    ClientExt -->|"Proxy Access (Port 8000)"| KongProxy["Kong API Gateway Proxy"]
    ClientExt -.->|"Direct Access Attempt"| Unexposed["🔒 Port 3000 Not Exposed<br>(Internal Service Only - Cannot Access)"]

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
> - **Cổng 3000 (Juice Shop)** là dịch vụ nội bộ (**Internal Service Only**) trong mạng `sentinel-net`. Cổng 3000 **không được expose/publish ra ngoài Host**, giúp ngăn ngừa hoàn toàn việc client truy cập trực tiếp vào backend mà bắt buộc phải đi qua bộ lọc Zero Trust của Kong Gateway.

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

## 3. Nội Dung Báo Cáo Tóm Tắt & Quy Trình Triển Khai

### 3.1 🎯 Ứng Dụng Mẫu & Môi Trường Thử Nghiệm
- **Backend Application**: Sử dụng OWASP Juice Shop (Docker Image: `bkimminich/juice-shop:latest`).
- **Network Isolation Policy**: Chạy trong Docker Bridge Network `sentinel-net`. Cổng 3000 **không được expose ra ngoài Host** (Internal Service Only) nhằm đảm bảo 100% lưu lượng bắt buộc phải đi qua API Gateway.

### 3.2 🛡️ Cấu Hình Hạ Tầng Kong API Gateway (Port 8000 & 8001)
- **Cổng Proxy (Port 8000)**: Điểm đầu vào duy nhất (Single Entrypoint) cho mọi lưu lượng từ bên ngoài.
- **Cổng Admin API (Port 8001)**: Dùng kiểm tra trạng thái và routes của Gateway. *(Khuyến nghị Production: Cần bảo mật bằng SSH Tunnel hoặc chặn public access)*.
- **Quản Lý Secret Bí Mật**: Secret API Key được khai báo qua biến `KONG_VAULT_ENV_AGENT_API_KEY` trong `.env` (`agent-secure-key-2026`). Script LuaJIT `render_config.lua` nạp động vào `/tmp/kong.yml` khi boot container mà không lưu secret thô trong Git.
- **Cơ Chế Bảo Vệ Hạ Tầng**:
  - **Giới hạn kích thước Payload**: Sử dụng `allowed_payload_size: 1` (chặn gửi file/payload lớn hơn 1MB).
  - **Giới hạn thời gian chờ (Timeouts)**: `connect_timeout: 5000ms`, `read_timeout: 5000ms`, `write_timeout: 5000ms` giúp bảo vệ Gateway không bị nghẽn kết nối và chống DoS/Slowloris nếu server đích sập.
  - **Giấu API Key với Backend**: Cấu hình `hide_credentials: true` trong plugin `key-auth` để Kong tự động bóc tách header `x-api-key` trước khi proxy tới Juice Shop.

### 3.3 🚦 Phân Luồng Routing, Phân Quyền ACL & Rate Limiting

| Tên Route | Danh sách Paths | Phương Thức (Methods) | Phân Quyền & Nhận Diện | Giới Hạn Tốc Độ (Rate Limit) |
|---|---|---|---|---|
| **`guest-route`** | `/api/Quantitys`, `/rest/products/search`, `/rest/admin/application-version`, `/rest/user/login`, `/rest/user/reset-password` | `GET`, `POST`, `OPTIONS` | Công khai (Guest / User / Agent) | 60 requests/phút |
| **`guest-register-route`** | `/api/Users`, `/api/SecurityAnswers` | `POST`, `OPTIONS` | Đăng ký tài khoản (Tách riêng để giới hạn method) | 20 requests/phút (Anti-Spam) |
| **`user-route`** | `/rest/basket`, `/api/BasketItems`, `/rest/user/whoami`, `/profile/image/file`, `/rest/order-history` | `GET`, `POST`, `PUT`, `DELETE`, `OPTIONS` | Đã đăng nhập (Yêu cầu Header `Authorization: Bearer <JWT>`) | 100 requests/phút |
| **`static-route`** | `/` (Catch-all) | `GET`, `POST`, `HEAD`, `OPTIONS` | Nạp giao diện web SPA (HTML/CSS/JS) | Theo Route |

- **Xác thực & Phân nhóm ACL**:
  - AI Agent dùng `key-auth` nhận diện `ai-agent` (`agent-group`), chỉ được truy cập các endpoint được cấp phép trong allowlist.
  - Request không có API Key đi qua `key-auth` với `anonymous: anonymous-user` (`guest-group`). Quyền JWT được backend Juice Shop kiểm tra *(Nhược điểm: Nếu hacker dùng JWT giả thì Gateway vẫn cho qua `user-route` do thiết kế Decoupled JWT)*.

### 3.4 📜 Quản Lý Allowlist Động Cho AI Agent (`config/allowlist.json`)
- Danh sách allowlist được lưu tại `config/allowlist.json` và nạp động tự động vào `pre-function` plugin bằng `render_config.lua` tại boot-time.
- **Endpoints AI Agent được phép**: `/api/Quantitys`, `/rest/products/search`, `/rest/user/login`.

### 3.5 🔧 Sự Cố Kỹ Thuật Đã Xử Lý & Vấn Đề Tồn Đọng

#### A. Sự Cố Đã Xử Lý (Route Shadowing Bug)
- **Vấn đề**: `agent-route` bị shadow bởi `guest-route` làm cho rate limit của Agent bị áp nhầm theo `guest-route` (60 req/min).
- **Nguyên nhân**: Thuật toán tính điểm (Point Scoring) của Kong 3.x Traditional Router ưu tiên route có số lượng path nhiều hơn (5 paths > 3 paths).
- **Giải pháp**: Triển khai `key-auth` ở cấp Service với `anonymous` fallback, xóa `agent-route` trùng lặp và cấu hình Consumer-Scoped Rate Limiting (**20 req/min**) cho `ai-agent`.

#### B. Các Vấn Đề Tồn Đọng & Thảo Luận Kỹ Thuật
1. **Vấn đề Cấu hình Method theo Route**:
   - `methods` áp dụng cho toàn bộ path trong cùng một route. Đã giải quyết cho `POST /api/Users` bằng cách tách riêng thành `guest-register-route`.
2. **Vấn đề Static Route `/` và khả năng truy cập Endpoint chưa liệt kê**:
   - *Câu hỏi*: Vấn đề xảy ra khi sử dụng static route `/` $\rightarrow$ Các endpoint chưa được đề cập trong route có bị truy cập được không? Có nên lập Denylist hay không?
   - *Trả lời*: Trong Kong Router, exact/prefix match có path dài hơn (như `/api/Quantitys`) luôn có độ ưu tiên cao hơn catch-all `/` của `static-route`. Tuy nhiên, do có sử dụng `/` để lấy được các endpoint giao diện từ web nên các endpoint chưa được nhắc tới trong route vẫn có thể truy cập được bình thường qua `/`, chưa thật sự deny endpoint đối với trường hợp của người dùng/tester.
3. **Vấn đề API Key truyền chuỗi rỗng (`""`)**:
   - *Câu hỏi*: Nếu API Key truyền là chuỗi rỗng `""` thì có truy cập được không?
   - *Trả lời*: Mã nguồn Lua trong `pre-function` kiểm tra `if key and key ~= "" then`. Nếu truyền `""`, Gateway sẽ xử lý như một request không có key (đưa về nhóm Guest) thay vì báo 401 Unauthorized.