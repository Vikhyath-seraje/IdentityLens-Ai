import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root before anything else
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

import streamlit as st
import pandas as pd
from backend.ai_engine import AIEngine
from backend.anomaly_detection import AnomalyDetectionEngine
from backend.identity_resolver import IdentityResolver

# ── Page header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">AI Response</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            AI Remediation Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Gemini AI analyses detected anomalies and generates step-by-step remediation plans.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,96,168,0.06);border:1px solid rgba(0,96,168,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#0060A8;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">GEMINI AI</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(14px)}
    to{opacity:1;transform:translateY(0)}
}
@keyframes shimmer {
    0%{background-position:200% center}
    100%{background-position:-200% center}
}
.section-title h2 {
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}
.kpi-insight { font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4; }
.ai-profile-card {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1.1rem 1.3rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    animation:fadeSlideUp 0.35s ease both;transition:box-shadow 0.2s;
}
.ai-profile-card:hover { box-shadow:0 4px 16px rgba(0,0,0,0.1); }
.anomaly-highlight {
    background:white;border:1px solid rgba(201,125,0,0.25);border-left:4px solid #D97706;
    border-radius:0 10px 10px 0;
    padding:1.1rem 1.3rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    animation:fadeSlideUp 0.35s ease both;
}
.ai-output-card {
    background:white;
    border:1px solid #E0E0E0;border-top:3px solid #E60028;
    border-radius:10px;padding:1.5rem 1.8rem;margin-top:0.75rem;
    box-shadow:0 2px 12px rgba(0,0,0,0.08);
    animation:fadeSlideUp 0.4s ease both;
}
.ai-output-header {
    display:flex;align-items:center;gap:0.6rem;
    font-size:0.65rem;text-transform:uppercase;letter-spacing:1.2px;
    color:#6B6B6B;font-weight:700;margin-bottom:1rem;
    padding-bottom:0.75rem;border-bottom:1px solid #E0E0E0;
}
.ai-badge {
    display:inline-flex;align-items:center;padding:0.18rem 0.55rem;
    background:linear-gradient(135deg,rgba(0,96,168,0.1),rgba(109,40,217,0.1));
    border:1px solid rgba(0,96,168,0.25);
    border-radius:100px;font-size:0.65rem;font-weight:700;
    color:#0060A8;letter-spacing:0.8px;
}
.how-gemini-works {
    background:linear-gradient(135deg,rgba(0,96,168,0.03),rgba(109,40,217,0.03));
    border:1px solid rgba(0,96,168,0.12);
    border-radius:10px;padding:1rem 1.2rem;margin-bottom:1.2rem;
    font-size:0.875rem;color:#4A4A4A;line-height:1.6;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

def get_ai_engine():
    """Always create a fresh AIEngine so env changes are picked up immediately."""
    return AIEngine()

@st.cache_data(ttl=300)
def get_anomalies_and_identities():
    anomaly_engine = AnomalyDetectionEngine()
    anomalies_df   = anomaly_engine.detect_anomalies()
    resolver       = IdentityResolver()
    identities_df  = resolver.get_resolved_identities()
    return anomalies_df, identities_df

ai_engine = get_ai_engine()
anomalies_df, identities_df = get_anomalies_and_identities()

# ── How it works banner ──────────────────────────────────────────────────────────
st.markdown("""
<div class="how-gemini-works">
    <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:#0060A8;
                margin-bottom:0.5rem;font-weight:700;">How This Works</div>
    Select a detected anomaly from the dropdown below, then click <strong>Generate Plan</strong>.
    Gemini AI will analyse the anomaly type, the affected identity's context (department, access level),
    and produce a <strong>prioritised, step-by-step remediation playbook</strong> tailored to your
    organisation's environment — in seconds.
</div>
""", unsafe_allow_html=True)

if anomalies_df.empty:
    st.success("No open anomalies found. Your system is clean — no remediation actions are needed right now. Keep monitoring for new threats.")
else:
    # ── Stats ────────────────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Open Anomalies", len(anomalies_df))
        st.markdown('<div class="kpi-insight">Awaiting remediation</div>', unsafe_allow_html=True)
    with col2:
        st.metric("Affected Identities", anomalies_df['identity_id'].nunique())
        st.markdown('<div class="kpi-insight">Unique accounts impacted</div>', unsafe_allow_html=True)
    with col3:
        top_type = anomalies_df['anomaly_type'].value_counts().index[0] if 'anomaly_type' in anomalies_df.columns else "—"
        st.metric("Most Common Issue", top_type[:18] + "…" if len(top_type) > 18 else top_type)
        st.markdown('<div class="kpi-insight">Highest frequency anomaly</div>', unsafe_allow_html=True)

    st.divider()

    # ── Anomaly Selector ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-title"><h2>Select an Anomaly to Remediate</h2></div>', unsafe_allow_html=True)

    display_df = anomalies_df.merge(
        identities_df[['identity_id', 'name', 'department']], on='identity_id', how='left'
    )
    options = display_df.apply(
        lambda x: f"[{x['anomaly_type']}]  {x.get('name', 'Unknown')}  ({x['identity_id']})", axis=1
    ).tolist()

    selected_option = st.selectbox(
        "Choose an anomaly from the list to generate a remediation plan:",
        options,
        help="Each entry shows [Anomaly Type] Identity Name (ID)"
    )

    if selected_option:
        idx = options.index(selected_option)
        row = display_df.iloc[idx]

        # Identity + Anomaly detail cards
        col_id, col_anomaly = st.columns(2)

        with col_id:
            st.markdown(f"""
            <div class="ai-profile-card">
                <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                            color:#6B6B6B;margin-bottom:0.8rem;font-weight:700;">AFFECTED IDENTITY</div>
                <div style="font-size:1.15rem;font-weight:800;color:#1A1A1A;margin-bottom:0.5rem;">
                    {row.get('name', 'Unknown')}
                </div>
                <div style="font-size:0.82rem;color:#4A4A4A;line-height:1.8;">
                    <div><strong>ID:</strong> <code>{row['identity_id']}</code></div>
                    <div><strong>Department:</strong> {row.get('department', '—')}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_anomaly:
            anomaly_type = row.get('anomaly_type', '—')
            description  = row.get('description', 'No description available.')
            st.markdown(f"""
            <div class="anomaly-highlight">
                <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                            color:#6B6B6B;margin-bottom:0.8rem;font-weight:700;">ANOMALY DETAILS</div>
                <div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:0.7rem;">
                    <span style="background:rgba(201,125,0,0.1);color:#C97D00;border:1px solid rgba(201,125,0,0.2);
                                 padding:0.2rem 0.65rem;border-radius:100px;font-size:0.7rem;font-weight:700;">
                        {anomaly_type}
                    </span>
                </div>
                <div style="font-size:0.87rem;color:#4A4A4A;line-height:1.6;">{description}</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        # ── AI Remediation Trigger ───────────────────────────────────────────────
        st.markdown('<div class="section-title"><h2>AI Remediation Plan Generator</h2></div>', unsafe_allow_html=True)

        col_btn, col_hint = st.columns([1, 3])
        with col_btn:
            generate = st.button("Generate Remediation Plan", type="primary", use_container_width=True)
        with col_hint:
            st.markdown(
                '<div style="font-size:0.83rem;color:#6B6B6B;padding-top:0.55rem;line-height:1.5;">'
                'Gemini AI will analyse the anomaly context and produce a <strong>prioritised, '
                'step-by-step remediation playbook</strong> tailored to this identity.'
                '</div>',
                unsafe_allow_html=True
            )

        if generate:
            with st.spinner("Gemini AI is analysing the anomaly and building your remediation plan…"):
                identity_context = (
                    f"ID: {row['identity_id']}, "
                    f"Name: {row.get('name', 'Unknown')}, "
                    f"Department: {row.get('department', '—')}"
                )
                anomaly_desc     = row.get('description', str(row['anomaly_type']))
                remediation_plan = ai_engine.get_remediation(anomaly_desc, identity_context)

            st.markdown(f"""
            <div class="ai-output-card">
                <div class="ai-output-header">
                    <span style="font-size:1.1rem;"></span>
                    AI-Generated Remediation Plan
                    <span class="ai-badge">Powered by Gemini AI</span>
                    <span style="margin-left:auto;font-size:0.72rem;color:#9E9E9E;">
                        For: {row.get('name','Unknown')} · {anomaly_type}
                    </span>
                </div>
            """, unsafe_allow_html=True)
            st.markdown(remediation_plan)
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("""
            <div style="margin-top:0.75rem;padding:0.65rem 1rem;
                        background:rgba(22,163,74,0.05);border:1px solid rgba(22,163,74,0.2);
                        border-radius:8px;font-size:0.82rem;color:#4A4A4A;">
                <strong>Next step:</strong> Review the plan above with your security team, then head to the
                <strong>Quarantine Center</strong> to isolate the identity while remediation is in progress.
            </div>
            """, unsafe_allow_html=True)
