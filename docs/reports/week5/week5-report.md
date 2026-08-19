# Báo Cáo Kỹ Thuật Tuần 5: Guardrails, phê duyệt thủ công và che dữ liệu nhạy cảm

## 🗺️ 1. Sơ Đồ Luồng Hoạt Động End-to-End (Data Flow)

```mermaid
flowchart TD
    USER(["👤 Người Dùng / Kỹ Sư"]):::client
    PROMPT["1. Lệnh Kiểm Thử"]:::client
    
    subgraph S1 ["🛡️ LỚP 1: BẢO VỆ ĐẦU VÀO"]
        INJ_CHECK{"Direct Injection?"}:::shield
        BLOCK_INJ["🛑 CHẶN ĐỨNG (CRITICAL)"]:::danger
    end

    subgraph S2 ["🧠 LỚP 2: AI AGENT & PHÂN TÍCH RỦI RO"]
        AGENT["2. AI Agent (Qwen) Đề Xuất"]:::agent
        RISK_ENG{"3. Phân Loại Rủi Ro<br/>(assess_request_risk)"}:::engine
    end

    subgraph S3 ["⚠️ LỚP 3: CHỐT CHẶN PHÊ DUYỆT (HITL)"]
        HITL_GATE{"Mức Rủi Ro?"}:::hitl
        HITL_CARD["4. Cảnh Báo Phê Duyệt"]:::hitl
        HITL_REJECT["🛑 REJECT (0 Socket, Log REJECTED)"]:::danger
        HITL_APPROVE["✅ APPROVE (Log APPROVED)"]:::success
    end

    subgraph S4 ["🌐 LỚP 4: THỰC THI QUA KONG GATEWAY"]
        SAFE_REQ["5. Safe Requester Client"]:::tool
        KONG["6. Kong API Gateway (Port 8000)<br/>• 429 Rate Limit | 413 Size | 403 ACL"]:::gateway
        JUICE["7. OWASP Juice Shop"]:::backend
    end

    subgraph S5 ["🛡️ LỚP 5: KHỬ KHUẨN & PHÒNG VỆ ĐẦU RA"]
        PII_MASK["8. Khử Khuẩn PII & Secret"]:::shield
        DELIMITER["9. Đóng Khung &lt;untrusted_http_response&gt;"]:::shield
    end

    subgraph S6 ["📊 LỚP 6: PHÂN TÍCH ĐỘNG & GHI NHẬT KÝ"]
        LLM_ASSESS["10. Real LLM Dynamic Assessment"]:::agent
        AUDIT_LOG[("11. Audit Log (.jsonl)")]:::log
        FINAL_REPORT["12. Báo Cáo An Ninh Tổng Hợp"]:::client
    end

    USER --> PROMPT --> INJ_CHECK
    INJ_CHECK -- "Phát hiện" --> BLOCK_INJ --> FINAL_REPORT
    INJ_CHECK -- "An toàn" --> AGENT --> RISK_ENG
    RISK_ENG --> HITL_GATE
    HITL_GATE -- "LOW" --> HITL_APPROVE
    HITL_GATE -- "MEDIUM / HIGH" --> HITL_CARD
    HITL_CARD -- "Từ chối (n/Enter)" --> HITL_REJECT --> AUDIT_LOG
    HITL_REJECT --> FINAL_REPORT
    HITL_CARD -- "Đồng ý (y)" --> HITL_APPROVE --> SAFE_REQ
    SAFE_REQ --> KONG --> JUICE --> KONG --> PII_MASK --> DELIMITER --> LLM_ASSESS
    LLM_ASSESS --> AUDIT_LOG
    LLM_ASSESS --> FINAL_REPORT --> USER

    classDef client fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1;
    classDef agent fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#4a148c;
    classDef shield fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20;
    classDef hitl fill:#fff8e1,stroke:#f57f17,stroke-width:2px,color:#e65100;
    classDef engine fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#bf360c;
    classDef tool fill:#fce4ec,stroke:#c2185b,stroke-width:2px,color:#880e4f;
    classDef gateway fill:#e0f2f1,stroke:#00695c,stroke-width:2px,color:#004d40;
    classDef backend fill:#eceff1,stroke:#37474f,stroke-width:2px,color:#263238;
    classDef danger fill:#ffebee,stroke:#c62828,stroke-width:2px,color:#b71c1c;
    classDef success fill:#e8f8f5,stroke:#117a65,stroke-width:2px,color:#0e6251;
    classDef log fill:#f5f5f5,stroke:#616161,stroke-width:2px,color:#212121;
```

---

## 🛡️ 2. Bảng Tổng Hợp 5 Trụ Cột Kỹ Thuật Cốt Lõi (Week 5 Pillars)

| Trụ Cột / Module | Vị Trí Code | Cơ Chế & Tính Năng Trọng Tâm | Kết Quả Đạt Được |
|---|---|---|---|
| **1. Khử Khuẩn PII & Data Redaction** | `tools/redactor.py` | • Che SĐT VN, CCCD 12 số, Thẻ Visa/Mastercard 16 số, Mật khẩu, DB URIs.<br>• `sanitize_llm_messages()` làm sạch ngữ cảnh trước khi gửi LLM. | 100% PII & Secrets được che giấu an toàn dạng `[REDACTED_*]`. |
| **2. Phòng Vệ Prompt Injection 2 Chiều** | `agent/guardrails.py`<br>`agent/system_prompt.txt` | • **Lớp vào**: Chặn câu lệnh người dùng cố ý bẻ khóa (Jailbreak/DAN/Secret exfiltration).<br>• **Lớp ra**: Bọc HTTP Response trong thẻ `<untrusted_http_response>`. | Triệt tiêu nguy cơ chiếm đoạt quyền điều khiển LLM song ngữ Anh - Việt. |
| **3. Phê Duyệt Rủi Ro (HITL Engine)** | `tools/safe_requester.py`<br>`agent/agent.py` | • Phân loại: `LOW` (tự chạy), `MEDIUM`/`HIGH` (bắt buộc duyệt), `CRITICAL` (chặn).<br>• Fail-Closed: Mặc định từ chối (`REJECTED_BY_USER`, 0 network socket). | Ngăn chặn hành động nguy hiểm (POST, Payload 1.5MB, Burst Test). |
| **4. Web UI Dashboard 4 Tabs** | `agent/ui.py` | • Tab 1: AI Agent (HITL Card, Real LLM, Live Probe).<br>• Tab 2: Manual Tester (Đánh giá rủi ro trước gửi).<br>• Tab 3: Audit Logs (.jsonl).<br>• Tab 4: Guardrails & Live PII Inspector. | Giao diện DevSecOps trực quan, realtime, quản trị thuận tiện. |
| **5. Chuẩn Hóa Test & Makefile** | `Makefile`<br>`tests/` | • `make test-week5`: Chạy toàn bộ 40 test cases.<br>• `make test-redaction`: Khử khuẩn văn bản nhập từ bàn phím.<br>• `make test-live-injection`: Kiểm chứng E2E với Real LLM Model.<br>• `make agent-interactive`: Chạy CLI Agent tương tác HITL. | Bộ tự động hóa hoàn chỉnh, dễ dàng tích hợp CI/CD pipeline. |

---

