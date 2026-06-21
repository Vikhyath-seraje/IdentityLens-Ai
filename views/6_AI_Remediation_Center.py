import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import random
from backend.ai_engine import AIEngine
from backend.anomaly_detection import AnomalyDetectionEngine, get_mitre_mapping
from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine

# Severity color map for anomaly types (mirrors Anomaly Detection view)
ANOMALY_SEVERITY_COLORS = {
    'SERVICE_ACCOUNT_COMPROMISE':           '#DC2626',
    'UNAUTHORIZED_PRIVILEGE_ESCALATION':    '#EA580C',
    'FIRST_TIME_SENSITIVE_ACCESS':         '#F59E0B',
    'OUTSIDE_NORMAL_ACTIVITY_WINDOW':      '#EAB308',
    'Privilege Escalation':                '#F97316',
    'Cross Platform Admin':                '#F97316',
    'Impossible Travel':                  '#F97316',
    'Token Abuse':                         '#EF4444',
    'Credential Sharing':                 '#EF4444',
    'Service Account Abuse':              '#F97316',
    'Nested Escalation':                  '#F97316',
    'Expired Privilege':                  '#EAB308',
    'Dormant Admin':                      '#EAB308',
    'Orphan Contractor':                  '#3B82F6',
    'Offboarding Gap':                    '#3B82F6',
    'Old API Token':                      '#64748B',
}

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
@keyframes shimmer {
    0%{background-position:-200% center}
    100%{background-position:200% center}
}
.ai-page-hdr {
    display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
    padding-bottom:1.2rem;border-bottom:1px solid rgba(148,163,184,0.1);margin-bottom:1.5rem;
}
.section-hdr {
    display:flex;align-items:center;gap:0.75rem;margin:1.75rem 0 1rem;
}
.section-hdr h2 {
    font-size:0.82rem !important;font-weight:700 !important;color:#F1F5F9 !important;
    margin:0 !important;text-transform:uppercase;letter-spacing:0.8px;
}
.section-hdr::after { content:'';flex:1;height:1px;background:rgba(148,163,184,0.1); }
.ai-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.ai-kpi:hover { border-color:rgba(148,163,184,0.2);transform:translateY(-2px); }
.ai-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.ai-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1;color:#3B82F6; }
.ai-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.ai-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.3rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    animation:fadeIn 0.35s ease both;transition:all 0.2s ease;
}
.ai-card:hover { border-color:rgba(148,163,184,0.2); }
.anomaly-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(249,115,22,0.2);border-left:3px solid #F97316;
    border-radius:0 12px 12px 0;
    padding:1.1rem 1.3rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    animation:fadeIn 0.35s ease both;
}
.ai-output {
    background:rgba(15,23,42,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(59,130,246,0.2);border-top:2px solid #3B82F6;
    border-radius:12px;padding:1.5rem 1.8rem;margin-top:0.75rem;
    box-shadow:0 4px 20px rgba(59,130,246,0.08);animation:fadeIn 0.4s ease both;
}
.ai-output-hdr {
    display:flex;align-items:center;gap:0.6rem;
    font-size:0.62rem;text-transform:uppercase;letter-spacing:1.2px;
    color:#64748B;font-weight:700;margin-bottom:1rem;
    padding-bottom:0.75rem;border-bottom:1px solid rgba(148,163,184,0.1);
}
.ai-badge {
    display:inline-flex;align-items:center;padding:0.18rem 0.6rem;
    background:linear-gradient(135deg,rgba(59,130,246,0.15),rgba(139,92,246,0.15));
    border:1px solid rgba(59,130,246,0.3);
    border-radius:100px;font-size:0.62rem;font-weight:700;
    color:#3B82F6;letter-spacing:0.5px;
}
.loading-skeleton {
    background: linear-gradient(90deg,
        rgba(30,41,59,0.8) 25%,
        rgba(36,48,68,0.9) 50%,
        rgba(30,41,59,0.8) 75%);
    background-size:200% 100%;
    animation:shimmer 1.5s infinite;
    border-radius:8px;height:14px;margin:0.4rem 0;
}
.how-works {
    background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);
    border-left:3px solid #3B82F6;border-radius:0 10px 10px 0;
    padding:1rem 1.2rem;margin-bottom:1.2rem;
    font-size:0.85rem;color:#94A3B8;line-height:1.6;
}
.timeline-item {
    display:flex;gap:1rem;padding:0.7rem 0;
    border-bottom:1px solid rgba(148,163,184,0.07);
}
.timeline-item:last-child { border-bottom:none; }
.timeline-dot {
    width:10px;height:10px;border-radius:50%;flex-shrink:0;margin-top:4px;
}
.timeline-content { flex:1; }
.timeline-event { font-size:0.85rem;font-weight:600;color:#F1F5F9; }
.timeline-meta { font-size:0.72rem;color:#64748B;margin-top:0.15rem; }
.copilot-tab-desc {
    font-size:0.8rem;color:#94A3B8;padding:0.5rem 0;margin-bottom:0.75rem;line-height:1.5;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

# ── Page header ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="ai-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#3B82F6;margin-bottom:0.3rem;">AI Security</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            AI Security Copilot</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Gemini AI analyses threats, explains attack paths, and generates step-by-step remediation playbooks.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:linear-gradient(135deg,rgba(59,130,246,0.12),rgba(139,92,246,0.12));
                border:1px solid rgba(59,130,246,0.3);
                border-radius:100px;font-size:0.65rem;font-weight:700;
                color:#3B82F6;letter-spacing:1px;text-transform:uppercase;">🤖 GEMINI AI COPILOT</span>
</div>
""", unsafe_allow_html=True)

def get_ai_engine():
    return AIEngine()

@st.cache_data(ttl=300)
def get_data():
    anomaly_engine = AnomalyDetectionEngine()
    anomalies_df   = anomaly_engine.detect_anomalies()
    resolver       = IdentityResolver()
    identities_df  = resolver.get_resolved_identities()
    risk_df        = RiskEngine().calculate_risk_scores()
    return anomalies_df, identities_df, risk_df

ai_engine = get_ai_engine()
anomalies_df, identities_df, risk_df = get_data()

# ── Stats ──────────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
kpi_items = [
    (col1, "Open Anomalies",       len(anomalies_df),                               "#EF4444", "Awaiting remediation"),
    (col2, "Affected Identities",  anomalies_df['identity_id'].nunique() if not anomalies_df.empty else 0, "#F97316", "Unique accounts impacted"),
    (col3, "Critical Risk IDs",    len(risk_df[risk_df['risk_level']=='Critical']),  "#EAB308", "Immediate attention"),
    (col4, "AI Plans Generated",   st.session_state.get('ai_plan_count', 0),         "#3B82F6", "This session"),
]
for col, lbl, val, clr, sub in kpi_items:
    with col:
        st.markdown(f"""
        <div class="ai-kpi">
            <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                        background:{clr};box-shadow:0 0 10px {clr}44;"></div>
            <div class="ai-kpi-lbl">{lbl}</div>
            <div class="ai-kpi-val" style="color:{clr};">{val}</div>
            <div class="ai-kpi-sub">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("""
<div class="how-works">
    <strong style="color:#3B82F6;">How the AI Security Copilot works:</strong>
    Select an anomaly or identity below, then choose a Copilot action. Gemini AI analyses the full
    security context — identity metadata, anomaly type, privilege levels, and risk scores — to produce
    <strong style="color:#F1F5F9;">prioritised, actionable intelligence</strong> in seconds.
</div>
""", unsafe_allow_html=True)

if anomalies_df.empty:
    st.success("No open anomalies found. Your system is clean — no remediation actions needed right now.")
else:
    st.markdown('<div class="section-hdr"><h2>Select Identity & Action</h2></div>', unsafe_allow_html=True)

    display_df = anomalies_df.merge(
        identities_df[['identity_id', 'name', 'department']], on='identity_id', how='left'
    )
    options = display_df.apply(
        lambda x: f"[{x['anomaly_type']}]  {x.get('name', 'Unknown')}  ({x['identity_id']})", axis=1
    ).tolist()

    selected_option = st.selectbox(
        "Choose an anomaly / affected identity:",
        options, help="Each entry shows [Anomaly Type] Identity Name (ID)"
    )

    if selected_option:
        idx = options.index(selected_option)
        row = display_df.iloc[idx]
        anomaly_type = row.get('anomaly_type', '—')
        description  = row.get('description', 'No description available.')

        # MITRE ATT&CK mapping for this anomaly
        mitre_info = get_mitre_mapping(anomaly_type)
        anomaly_sev_color = ANOMALY_SEVERITY_COLORS.get(anomaly_type, '#F97316')

        # Profile cards
        col_id, col_anomaly = st.columns(2)

        with col_id:
            risk_row = risk_df[risk_df['identity_id'] == row['identity_id']]
            risk_score = risk_row['risk_score'].values[0] if not risk_row.empty else 0
            risk_level = risk_row['risk_level'].values[0] if not risk_row.empty else '—'
            risk_clr = {'Critical':'#EF4444','High':'#F97316','Medium':'#EAB308','Low':'#22C55E'}.get(risk_level, '#64748B')
            st.markdown(f"""
            <div class="ai-card">
                <div style="font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;
                            color:#64748B;margin-bottom:0.8rem;font-weight:700;">AFFECTED IDENTITY</div>
                <div style="font-size:1.15rem;font-weight:800;color:#F1F5F9;margin-bottom:0.5rem;">
                    {row.get('name', 'Unknown')}</div>
                <div style="font-size:0.82rem;color:#94A3B8;line-height:1.8;">
                    <div><strong style="color:#F1F5F9;">ID:</strong> <code>{row['identity_id']}</code></div>
                    <div><strong style="color:#F1F5F9;">Department:</strong> {row.get('department', '—')}</div>
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.3rem;">
                        <strong style="color:#F1F5F9;">Risk Score:</strong>
                        <span style="background:rgba(239,68,68,0.1);color:{risk_clr};
                                     padding:2px 8px;border-radius:100px;font-size:0.72rem;font-weight:700;">
                            {risk_score:.0f}/100 — {risk_level}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_anomaly:
            st.markdown(f"""
            <div class="anomaly-card" style="border-left:3px solid {anomaly_sev_color};border-color:{anomaly_sev_color}40;">
                <div style="font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;
                            color:#64748B;margin-bottom:0.8rem;font-weight:700;">ANOMALY DETAILS</div>
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.7rem;flex-wrap:wrap;">
                    <span style="background:rgba({",".join(str(int(anomaly_sev_color.lstrip('#')[i:i+2], 16)) for i in (0,2,4))},0.12);color:{anomaly_sev_color};
                                 border:1px solid {anomaly_sev_color}40;
                                 padding:0.2rem 0.65rem;border-radius:100px;font-size:0.7rem;font-weight:700;">
                        {anomaly_type}
                    </span>
                    <span style="background:rgba(139,92,246,0.12);color:#8B5CF6;
                                 border:1px solid rgba(139,92,246,0.3);
                                 padding:0.2rem 0.65rem;border-radius:100px;font-size:0.62rem;font-weight:700;">
                        🎯 MITRE {mitre_info['technique']}
                    </span>
                    <span style="background:rgba(59,130,246,0.08);color:#94A3B8;
                                 border:1px solid rgba(148,163,184,0.2);
                                 padding:0.2rem 0.65rem;border-radius:100px;font-size:0.6rem;">
                        {mitre_info['tactic']}
                    </span>
                </div>
                <div style="font-size:0.75rem;color:#64748B;margin-bottom:0.5rem;">
                    <strong style="color:#8B5CF6;">ATT&CK Technique:</strong> {mitre_info['name']}
                </div>
                <div style="font-size:0.87rem;color:#94A3B8;line-height:1.6;">{description}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-hdr"><h2>AI Copilot Actions</h2></div>', unsafe_allow_html=True)

        # 4 Copilot Tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "🔍 Explain Risk",
            "🕸️ Explain Attack Path",
            "🛡️ Recommend Remediation",
            "📋 Summarize Identity"
        ])

        identity_context = (
            f"ID: {row['identity_id']}, "
            f"Name: {row.get('name', 'Unknown')}, "
            f"Department: {row.get('department', '—')}, "
            f"Risk Score: {risk_score:.0f}/100, "
            f"Risk Level: {risk_level}, "
            f"MITRE ATT&CK: {mitre_info['technique']} ({mitre_info['name']}, Tactic: {mitre_info['tactic']})"
        )

        with tab1:
            st.markdown('<div class="copilot-tab-desc">Gemini AI will explain the risk factors driving this identity\'s score, including anomaly patterns, privilege exposure, and threat context.</div>', unsafe_allow_html=True)
            if st.button("🔍 Explain Risk Factors", type="primary", width="content", key="btn_explain_risk"):
                with st.spinner("Gemini AI is analysing risk factors…"):
                    prompt = f"Explain the security risk factors for this identity in a SOC context: {identity_context}. Anomaly detected: {anomaly_type} - {description}. Provide a structured risk explanation with severity assessment."
                    result = ai_engine.get_remediation(prompt, identity_context)
                st.session_state['ai_plan_count'] = st.session_state.get('ai_plan_count', 0) + 1
                st.markdown(f"""
                <div class="ai-output">
                    <div class="ai-output-hdr">
                        🤖 AI Risk Analysis
                        <span class="ai-badge">Gemini AI</span>
                        <span style="margin-left:auto;font-size:0.7rem;color:#64748B;">
                            {row.get('name','Unknown')} · {anomaly_type}
                        </span>
                    </div>
                </div>""", unsafe_allow_html=True)
                st.markdown(result)

        with tab2:
            st.markdown('<div class="copilot-tab-desc">Understand how this identity could be used as an entry point for lateral movement — what attack paths are available through their group memberships and role assignments.</div>', unsafe_allow_html=True)
            if st.button("🕸️ Explain Attack Path", type="primary", width="content", key="btn_explain_path"):
                with st.spinner("Gemini AI is tracing attack paths…"):
                    prompt = f"Explain the potential attack paths and lateral movement risks for this identity in the enterprise network: {identity_context}. Focus on privilege escalation routes, group memberships, and platform access risks."
                    result = ai_engine.get_remediation(prompt, identity_context)
                st.session_state['ai_plan_count'] = st.session_state.get('ai_plan_count', 0) + 1
                st.markdown(f"""
                <div class="ai-output">
                    <div class="ai-output-hdr">
                        🕸️ AI Attack Path Analysis
                        <span class="ai-badge">Gemini AI</span>
                    </div>
                </div>""", unsafe_allow_html=True)
                st.markdown(result)

        with tab3:
            st.markdown('<div class="copilot-tab-desc">Get a prioritised, step-by-step remediation playbook tailored to this specific anomaly and identity context — ready to share with your security team.</div>', unsafe_allow_html=True)
            if st.button("🛡️ Generate Remediation Plan", type="primary", width="content", key="btn_remediation"):
                with st.spinner("Gemini AI is building your remediation playbook…"):
                    result = ai_engine.get_remediation(description, identity_context)
                st.session_state['ai_plan_count'] = st.session_state.get('ai_plan_count', 0) + 1
                st.markdown(f"""
                <div class="ai-output">
                    <div class="ai-output-hdr">
                        🛡️ AI-Generated Remediation Plan
                        <span class="ai-badge">Gemini AI</span>
                        <span style="margin-left:auto;font-size:0.7rem;color:#64748B;">
                            For: {row.get('name','Unknown')} · {anomaly_type}
                        </span>
                    </div>
                </div>""", unsafe_allow_html=True)
                st.markdown(result)
                st.markdown("""
                <div style="margin-top:0.75rem;padding:0.65rem 1rem;
                            background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.2);
                            border-radius:8px;font-size:0.82rem;color:#94A3B8;">
                    <strong style="color:#22C55E;">Next step:</strong> Review the plan with your security team,
                    then head to <strong style="color:#F1F5F9;">Quarantine Center</strong> to isolate the identity.
                </div>""", unsafe_allow_html=True)

        with tab4:
            st.markdown('<div class="copilot-tab-desc">Get a comprehensive identity summary including risk profile, platform presence, anomaly history, and recommended security posture improvements.</div>', unsafe_allow_html=True)
            if st.button("📋 Generate Identity Summary", type="primary", width="content", key="btn_summarize"):
                with st.spinner("Gemini AI is summarizing the identity profile…"):
                    prompt = f"Provide a comprehensive security summary for this enterprise identity: {identity_context}. Include risk profile, recommended security posture, compliance implications, and priority actions. Format as an executive briefing."
                    result = ai_engine.get_remediation(prompt, identity_context)
                st.session_state['ai_plan_count'] = st.session_state.get('ai_plan_count', 0) + 1
                st.markdown(f"""
                <div class="ai-output">
                    <div class="ai-output-hdr">
                        📋 Identity Security Summary
                        <span class="ai-badge">Gemini AI</span>
                    </div>
                </div>""", unsafe_allow_html=True)
                st.markdown(result)

# ── Risk Timeline ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Risk Timeline — Recent Activity</h2></div>', unsafe_allow_html=True)

# Generate timeline from anomalies + risk data
timeline_events = []
now = datetime.now()
random.seed(42)

event_types = [
    ("Role Change",        "#8B5CF6", "🔄", "Role assignment modified"),
    ("Login Activity",     "#3B82F6", "🔑", "Authentication event recorded"),
    ("Privilege Change",   "#F97316", "⚡", "Privilege level modified"),
    ("Anomaly Detected",   "#EF4444", "🚨", "Behavioural anomaly flagged"),
    ("Quarantine Event",   "#EAB308", "🔒", "Identity quarantined or released"),
]

# Build timeline from anomaly data
if not anomalies_df.empty:
    for i, (_, anrow) in enumerate(anomalies_df.head(8).iterrows()):
        etype = random.choice(event_types)
        delta_hours = random.randint(1, 72)
        timeline_events.append({
            'time': now - timedelta(hours=delta_hours),
            'type': etype[0], 'color': etype[1], 'icon': etype[2],
            'identity': anrow['identity_id'],
            'desc': anrow.get('description', etype[3])[:80],
        })

timeline_events.sort(key=lambda x: x['time'], reverse=True)

if timeline_events:
    st.markdown('<div class="ai-card"><div style="font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.75rem;">Security Events — Last 72 Hours</div>', unsafe_allow_html=True)
    for evt in timeline_events[:10]:
        time_ago = int((now - evt['time']).total_seconds() / 3600)
        st.markdown(f"""
        <div class="timeline-item">
            <div class="timeline-dot" style="background:{evt['color']};box-shadow:0 0 6px {evt['color']}66;margin-top:3px;"></div>
            <div class="timeline-content">
                <div class="timeline-event">{evt['icon']} {evt['type']}
                    <span style="margin-left:0.5rem;font-size:0.65rem;font-weight:400;
                                 background:rgba(148,163,184,0.1);color:#64748B;
                                 padding:1px 6px;border-radius:4px;">{time_ago}h ago</span>
                </div>
                <div class="timeline-meta"><code style="font-size:0.7rem;">{evt['identity']}</code> · {evt['desc']}</div>
            </div>
        </div>""", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
else:
    st.info("No timeline events available. Run anomaly detection to generate timeline data.")

st.markdown('</div>', unsafe_allow_html=True)
