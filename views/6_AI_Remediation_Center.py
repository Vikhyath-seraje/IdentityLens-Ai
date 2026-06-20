import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
from backend.ai_engine import AIEngine
from backend.anomaly_detection import AnomalyDetectionEngine
from backend.identity_resolver import IdentityResolver

st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">AI Response</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            AI Remediation Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Gemini-powered automated remediation plans and security policy generation.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,96,168,0.06);border:1px solid rgba(0,96,168,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#0060A8;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">GEMINI AI</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
@st.cache_resource
def get_ai_engine():
    return AIEngine()

@st.cache_data
def get_anomalies_and_identities():
    anomaly_engine = AnomalyDetectionEngine()
    anomalies_df   = anomaly_engine.detect_anomalies()
    resolver       = IdentityResolver()
    identities_df  = resolver.get_resolved_identities()
    return anomalies_df, identities_df

ai_engine = get_ai_engine()
anomalies_df, identities_df = get_anomalies_and_identities()

if anomalies_df.empty:
    st.success("✅ No anomalies detected. System posture is healthy — no remediation needed.")
else:
    # ── Stats ──────────────────────────────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        st.metric("🚨 Open Anomalies", len(anomalies_df))
    with col2:
        st.metric("🆔 Affected Identities", anomalies_df['identity_id'].nunique())

    st.divider()

    # ── Anomaly Selector ───────────────────────────────────────────────────
    st.markdown('<div class="section-title"><h2>Select Anomaly to Remediate</h2></div>', unsafe_allow_html=True)

    display_df = anomalies_df.merge(
        identities_df[['identity_id', 'name', 'department']], on='identity_id', how='left'
    )
    options = display_df.apply(
        lambda x: f"[{x['anomaly_type']}]  {x.get('name','Unknown')}  ({x['identity_id']})", axis=1
    ).tolist()

    selected_option = st.selectbox("Detected anomalies:", options)

    if selected_option:
        idx = options.index(selected_option)
        row = display_df.iloc[idx]

        # Identity card
        col_id, col_anomaly = st.columns(2)
        with col_id:
            st.markdown(f"""
            <div class="info-card">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:0.8rem;">AFFECTED IDENTITY</div>
                <div style="font-size:1.1rem;font-weight:700;color:#e2e8f0;margin-bottom:0.4rem;">{row.get('name','Unknown')}</div>
                <div style="font-size:0.82rem;color:#94a3b8;margin-bottom:0.2rem;">🆔 {row['identity_id']}</div>
                <div style="font-size:0.82rem;color:#94a3b8;">🏢 {row.get('department','—')}</div>
            </div>
            """, unsafe_allow_html=True)

        with col_anomaly:
            st.markdown(f"""
            <div class="info-card" style="border-color:rgba(245,158,11,0.2);">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:0.8rem;">ANOMALY DETAILS</div>
                <span class="badge badge-high" style="margin-bottom:0.6rem;display:inline-block;">{row['anomaly_type']}</span>
                <div style="font-size:0.87rem;color:#94a3b8;line-height:1.5;">{row.get('description','No description available.')}</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ── AI Remediation ─────────────────────────────────────────────────
        st.markdown('<div class="section-title"><h2>AI Remediation Plan Generator</h2></div>', unsafe_allow_html=True)

        col_btn, col_hint = st.columns([1, 3])
        with col_btn:
            generate = st.button("⚡ Generate Remediation Plan", type="primary", use_container_width=True)
        with col_hint:
            st.markdown('<div style="font-size:0.82rem;color:#64748b;padding-top:0.5rem;">Gemini AI will analyse the anomaly context and generate a prioritised, step-by-step remediation plan.</div>', unsafe_allow_html=True)

        if generate:
            with st.spinner("🤖 Analysing risk context and generating remediation plan with Gemini AI…"):
                identity_context = f"ID: {row['identity_id']}, Name: {row.get('name','Unknown')}, Department: {row.get('department','—')}"
                anomaly_desc     = row.get('description', str(row['anomaly_type']))
                remediation_plan = ai_engine.get_remediation(anomaly_desc, identity_context)

            st.markdown("""
            <div style="background:linear-gradient(135deg,rgba(0,212,255,0.05),rgba(139,92,246,0.05));border:1px solid rgba(0,212,255,0.15);border-radius:14px;padding:1.5rem 1.8rem;margin-top:0.5rem;">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:1rem;">⚡ AI-GENERATED REMEDIATION PLAN</div>
            """, unsafe_allow_html=True)
            st.markdown(remediation_plan)
            st.markdown("</div>", unsafe_allow_html=True)
