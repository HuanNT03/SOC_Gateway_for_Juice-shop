# Báo Cáo Tuần 4 - Kong API Gateway

## Sơ Đồ Kiến Trúc Hạ Tầng Kong API Gateway & Network Isolation

```mermaid
flowchart TD
    Client["External Clients / AI Agent / Tester"] -->|"Port 8000"| KongProxy["Kong Proxy"]
    Admin["DevSecOps Admin"] -->|"Port 8001"| KongAdmin["Kong Admin API"]
    
    subgraph IsolatedNetwork["Kong Gateway & Zero Trust Security Enforcement"]
        KongProxy --> GlobalSecurity{"Global Payload Size Control<br>(1MB Max Limit)"}
        
        GlobalSecurity -->|"Exceeded Limit"| RespGlobalFail["413 Payload Too Large"]
        GlobalSecurity -->|"Pass"| Router{"Route Evaluation & Matching"}
        
        Router -->|"No Route Matched"| Resp404["404 Not Found"]
        
        Router --> RouteAgent["Route 1: agent-route<br>(Headers: x-api-key ~.+)"]
        Router --> RouteGuest["Route 2: guest-route<br>(Rate Limit: 60/min)"]
        Router --> RouteRegister["Route 3: guest-register-route<br>(POST-only, Rate Limit: 20/min)"]
        Router --> RouteUser["Route 4: user-route<br>(Headers: Bearer JWT)"]
        Router --> RouteStatic["Route 5: static-route<br>(Catch-all SPA Assets)"]
        
        RouteAgent --> AgentCheck{"Key-Auth & ACL Enforcement<br>(Vault Dynamic Key Resolution)"}
        AgentCheck -->|"Invalid API Key"| Resp401["401 Unauthorized"]
        AgentCheck -->|"Valid API Key & agent-group"| JuiceShop
        
        RouteGuest --> ACLCheckGuest{"ACL Deny Check"}
        ACLCheckGuest -->|"agent-group"| Resp403["403 Forbidden"]
        ACLCheckGuest -->|"guest-group"| JuiceShop
        
        RouteRegister --> ACLCheckRegister{"ACL Deny Check"}
        ACLCheckRegister -->|"agent-group"| Resp403
        ACLCheckRegister -->|"guest-group"| JuiceShop
        
        RouteUser --> UserHeaderCheck{"Header & ACL Check<br>(Bearer JWT)"}
        UserHeaderCheck -->|"agent-group"| Resp403
        UserHeaderCheck -->|"Missing Bearer Header"| Resp404
        UserHeaderCheck -->|"Valid Header & guest-group"| JuiceShop
        
        RouteStatic --> ACLCheckStatic{"ACL Deny Check"}
        ACLCheckStatic -->|"agent-group"| Resp403
        ACLCheckStatic -->|"guest-group"| JuiceShop
    end
    
    JuiceShop["OWASP Juice Shop<br>(web:3000 - Internal Network Only)"]
```

---

## Luồng Hoạt Động Kiến Trúc Decoupled JWT & Zero Trust RBAC

```mermaid
sequenceDiagram
    autonumber
    actor Agent as AI Security Agent / Attacker
    actor Client as Guest / User Client
    participant Kong as Kong Gateway (Port 8000)
    participant Juice as Juice Shop (Backend web:3000)

    Note over Agent, Kong: Kịch bản 1: AI Agent dùng API Key hợp lệ gọi Endpoint được phép
    Agent->>Kong: GET /api/Quantitys/ (Header: x-api-key: {vault://env/agent-api-key})
    Note over Kong: Khớp agent-route -> Key-Auth xác thực ai-agent -> ACL allow agent-group
    Kong->>Juice: Proxy Request sang Backend (Redacted API Key)
    Juice-->>Kong: HTTP 200 OK (Data)
    Kong-->>Agent: HTTP 200 OK (Data - Rate Limit: 20/min)

    Note over Agent, Kong: Kịch bản 2: AI Agent dùng API Key cố tình truy cập Route khác (Vượt quyền)
    Agent->>Kong: GET /ftp/ hoặc GET /rest/basket (Header: x-api-key)
    Note over Kong: Khớp Route tương ứng -> Key-Auth nhận diện agent-group -> ACL deny agent-group
    Kong-->>Agent: HTTP 403 Forbidden ("You cannot consume this service")

    Note over Agent, Kong: Kịch bản 3: Attacker truyền SAI API Key
    Agent->>Kong: GET /api/Quantitys/ (Header: x-api-key: fake-invalid-key)
    Note over Kong: Khớp agent-route -> Key-Auth kiểm tra Key -> Thất bại
    Kong-->>Agent: HTTP 401 Unauthorized ("Invalid authentication credentials")

    Note over Client, Juice: Kịch bản 4: Khách / User truy cập trang Web công khai
    Client->>Kong: GET / (No API Key)
    Note over Kong: Khớp static-route -> Key-Auth gán anonymous-user (guest-group) -> Pass ACL
    Kong->>Juice: Proxy Request sang Backend
    Juice-->>Kong: HTTP 200 OK (Index.html / Frontend Assets)
    Kong-->>Client: HTTP 200 OK (Frontend Assets)
```

---

## Tóm Tắt Cấu Hình Bảo Mật

1. **Bảo Mật API Key Không Hardcode**:
   - Sử dụng plugin **Kong Vault Environment** (`{vault://env/agent-api-key}`).
   - Đọc trực tiếp secret từ biến môi trường `KONG_VAULT_ENV_AGENT_API_KEY` trong `docker-compose.yml`.

2. **Chặn AI Agent Vượt Quyền (403 Forbidden)**:
   - Các Route công khai (`guest-route`, `guest-register-route`, `user-route`, `static-route`) đều được trang bị plugin `acl` cấu hình `deny: [agent-group]`.
   - Nếu AI Agent mang `x-api-key` truy cập ngoài phạm vi 3 endpoint được phép (`/api/Quantitys`, `/rest/products/search`, `/rest/user/login`), Kong sẽ lập tức trả về **`403 Forbidden`**.

3. **Chặn API Key Giả Mạo / Sai (401 Unauthorized)**:
   - Route `agent-route` áp dụng `key-auth` nghiêm ngặt (không có fallback anonymous).
   - Nếu gửi API Key sai, Kong chặn ngay tại Gateway với **`401 Unauthorized`**.

4. **Phân Tách Rate Limiting Độc Lập**:
   - `agent-route`: 20 requests/phút.
   - `guest-route`: 60 requests/phút.
   - `guest-register-route`: 20 requests/phút (Anti-Spam).
   - `user-route`: 100 requests/phút.
   - `static-route`: Không giới hạn (đảm bảo trải nghiệm nạp mượt mà giao diện SPA).
