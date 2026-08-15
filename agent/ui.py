"""
Project Sentinel - DevSecOps & AI Gateway
Module: Streamlit Web UI Dashboard (agent/ui.py)

Mục đích:
    Giao diện điều khiển trực quan dành cho AI Security Agent và DevSecOps.
    - Tương tác tự nhiên với Agent kiểm thử bảo mật API Gateway.
    - Chạy thủ công các HTTP Request & Burst Rate Limit Test.
    - Giám sát nhật ký Audit Log (.jsonl) thời gian thực với dữ liệu đã được làm sạch.

Sử dụng:
    streamlit run agent/ui.py
"""

import os
import sys
import json
import streamlit as st
from typing import List, Dict, Any
from dotenv import load_dotenv

# Tự động nạp môi trường từ .env
load_dotenv()

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from agent.agent import analyze_user_request, generate_proposal, execute_proposal, format_agent_report
from tools.safe_requester import send_request, burst_test, load_payloads_dict, DEFAULT_GATEWAY_HOST
from tools.logger import DEFAULT_LOG_FILE


def load_audit_logs(log_file: str = DEFAULT_LOG_FILE) -> List[Dict[str, Any]]:
    """Nạp danh sách bản ghi Audit Log từ tệp JSONL.

    Inputs:
        log_file (str): Đường dẫn tệp log JSONL.

    Outputs:
        list[dict]: Danh sách các bản ghi log dạng dict (mới nhất xếp trước).
    """
    if not os.path.exists(log_file):
        return []
    logs = []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
    except Exception as e:
        print(f"[UI ERROR] Failed to read log file: {e}")
    return list(reversed(logs))


def get_status_badge_html(status_code: int) -> str:
    """Tạo badge màu sắc tương ứng với HTTP Status Code.

    Inputs:
        status_code (int): Mã phản hồi HTTP.

    Outputs:
        str: Chuỗi HTML hiển thị badge.
    """
    if status_code == 200:
        return f'<span style="background-color:#28a745;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;">200 OK</span>'
    elif status_code == 403:
        return f'<span style="background-color:#dc3545;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;">403 Forbidden</span>'
    elif status_code == 413:
        return f'<span style="background-color:#fd7e14;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;">413 Payload Too Large</span>'
    elif status_code == 429:
        return f'<span style="background-color:#ffc107;color:black;padding:3px 8px;border-radius:4px;font-weight:bold;">429 Rate Limited</span>'
    elif status_code == 401:
        return f'<span style="background-color:#e83e8c;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;">401 Unauthorized</span>'
    else:
        return f'<span style="background-color:#6c757d;color:white;padding:3px 8px;border-radius:4px;font-weight:bold;">{status_code}</span>'


def render_ui():
    """Hàm dựng giao diện chính của ứng dụng Streamlit."""
    st.set_page_config(
        page_title="Project Sentinel - AI Security Dashboard",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ Project Sentinel: AI Security Agent & Gateway Dashboard")
    st.caption("OWASP Juice Shop + Kong API Gateway (v3.6) + AI Security Agent")

    tabs = st.tabs(["🤖 AI Security Agent", "⚡ Manual HTTP Tester", "📜 Audit Log Inspector"])

    # TAB 1: AI SECURITY AGENT
    with tabs[0]:
        st.subheader("Trợ Lý Kiểm Thử AI Agent (Interactive Mode)")
        st.markdown("Nhập câu lệnh bằng ngôn ngữ tự nhiên hoặc bấm nút kịch bản mẫu bên dưới:")

        if "selected_prompt" not in st.session_state:
            st.session_state["selected_prompt"] = "Hãy kiểm tra rate limit của endpoint /api/Quantitys với 30 request"
        if "auto_run" not in st.session_state:
            st.session_state["auto_run"] = False

        def _select_preset(text: str):
            st.session_state["selected_prompt"] = text
            st.session_state["auto_run"] = True

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.button("🔥 Rate Limit Test", on_click=_select_preset, args=("Hãy kiểm tra rate limit của endpoint /api/Quantitys với 30 request",))
        with col2:
            st.button("🚫 Forbidden ACL Test", on_click=_select_preset, args=("Thử truy cập vào endpoint admin /rest/admin/application-version",))
        with col3:
            st.button("📦 1.5MB Oversized Test", on_click=_select_preset, args=("Gửi file lớn hoặc oversized payload để test gateway",))
        with col4:
            st.button("💉 Special Chars Probe", on_click=_select_preset, args=("Thử chèn ký tự đặc biệt vào search endpoint",))

        user_input = st.text_input(
            "Câu lệnh kiểm thử:",
            value=st.session_state["selected_prompt"]
        )

        should_run = st.button("🚀 Thực Thi Lệnh Agent", type="primary") or st.session_state["auto_run"]
        if st.session_state["auto_run"]:
            st.session_state["auto_run"] = False

        if should_run:
            with st.spinner("Agent đang phân tích kịch bản và gửi request qua Gateway..."):
                proposal = generate_proposal(user_input)

                if proposal.get("used_llm"):
                    st.success(f"🤖 **Real LLM Agent ({proposal.get('model', 'Qwen')})** đang xử lý yêu cầu.")
                else:
                    raw_err = proposal.get("fallback_reason") or "AI_AGENT_API_KEY chưa được khai báo trong .env"
                    st.error(f"⚠️ **CHẾ ĐỘ DỰ PHÒNG (Rule-based Engine Fallback)**\n\n**THÔNG BÁO LỖI THỰC TẾ TỪ LLM API / HỆ THỐNG**:\n```text\n{raw_err}\n```")

                st.info(f"**Kịch bản đề xuất**: {proposal['scenario_name']}\n\n**Chi tiết**: {proposal['explanation']}")
                
                result = execute_proposal(proposal)
                report = format_agent_report(result)

                st.markdown("### 📊 Kết Quả Báo Cáo An Ninh")
                st.markdown(report)

    # TAB 2: MANUAL HTTP TESTER
    with tabs[1]:
        st.subheader("Kiểm Thử Thủ Công qua Kong Gateway")
        c1, c2, c3 = st.columns([3, 1, 1])

        with c1:
            endpoint = st.text_input("Endpoint Path:", value="/api/Quantitys")
        with c2:
            method = st.selectbox("HTTP Method:", ["GET", "POST", "OPTIONS"])
        with c3:
            count = st.number_input("Số Request (Burst Test):", min_value=1, max_value=50, value=1)

        payloads = load_payloads_dict()
        category_options = list(payloads.keys()) if payloads else ["long_string"]

        c4, c5 = st.columns(2)
        with c4:
            category = st.selectbox("Payload Category:", category_options)
        with c5:
            approved_vals = payloads.get(category, [""]) if isinstance(payloads.get(category), list) else ["N/A"]
            chosen_val = st.selectbox("Payload Value:", approved_vals)

        if st.button("Gửi Request Test", type="secondary"):
            with st.spinner("Đang gửi request..."):
                if count > 1:
                    res = burst_test(endpoint, count=count, method=method)
                    st.json(res)
                else:
                    payload = chosen_val if category != "oversized_payload" else None
                    res = send_request(endpoint, method=method, payload=payload)
                    st.json(res)

    # TAB 3: AUDIT LOG INSPECTOR
    with tabs[2]:
        st.subheader("Nhật Ký Truy Vấn Gateway Audit Logs (`logs/gateway_audit.jsonl`)")

        if st.button("🔄 Tải Lại Nhật Ký Log"):
            st.rerun()

        logs = load_audit_logs()
        if not logs:
            st.warning("Chưa có nhật ký audit log nào trong tệp `logs/gateway_audit.jsonl`.")
        else:
            st.success(f"Hiển thị {len(logs)} bản ghi log gần nhất (Đã được làm sạch 100% secret):")
            for idx, item in enumerate(logs[:30]):
                status_html = get_status_badge_html(item.get("status_code", 0))
                with st.expander(f"[{item.get('timestamp')}] {item.get('method')} {item.get('endpoint')} -> {item.get('status_code')}"):
                    st.markdown(f"**Trạng thái**: {status_html}", unsafe_allow_html=True)
                    st.markdown(f"**Thời gian xử lý**: {item.get('duration_ms')} ms")
                    st.markdown("**Request Headers (Masked)**:")
                    st.json(item.get("request_headers", {}))
                    st.markdown("**Response Headers (Masked)**:")
                    st.json(item.get("response_headers", {}))
                    st.markdown("**Response Body Snippet (Masked)**:")
                    st.code(item.get("response_body_snippet", ""))


if __name__ == "__main__":
    render_ui()
