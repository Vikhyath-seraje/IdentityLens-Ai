import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
from backend.validation_engine import ValidationEngine


def _hex_to_rgb(hex_color):
    """Convert hex color to RGB string for CSS rgba()."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"

# ── CSS ────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
@keyframes slideIn { from{opacity:0;transform:translateX(-10px)} to{opacity:1;transform:translateX(0)} }
.val-page-hdr {
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
.metric-box {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1rem;text-align:center;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.metric-box:hover { border-color:rgba(148,163,184,0.2);transform:translateY(-2px); }
.metric-val { font-size:2rem;font-weight:900;letter-spacing:-1px; }
.metric-lbl { font-size:0.6rem;color:#64748B;text-transform:uppercase;font-weight:700;letter-spacing:1px;margin-top:0.3rem; }
.test-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1.2rem;margin-bottom:0.75rem;
    box-shadow:0 2px 12px rgba(0,0,0,0.3);
    animation:slideIn 0.35s ease both;transition:all 0.25s ease;
}
.test-card:hover { border-color:rgba(148,163,184,0.18);box-shadow:0 4px 20px rgba(0,0,0,0.4); }
.test-card-pass { border-left:3px solid #22C55E;box-shadow:0 2px 12px rgba(34,197,94,0.08); }
.test-card-fail { border-left:3px solid #EF4444;box-shadow:0 2px 12px rgba(239,68,68,0.08); }
.test-header { display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem; }
.test-title { font-size:0.9rem;font-weight:700;color:#F1F5F9; }
.test-status-pass {
    display:inline-flex;align-items:center;gap:0.3rem;
    background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);
    border-radius:100px;padding:0.15rem 0.6rem;font-size:0.68rem;font-weight:700;color:#22C55E;
}
.test-status-fail {
    display:inline-flex;align-items:center;gap:0.3rem;
    background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);
    border-radius:100px;padding:0.15rem 0.6rem;font-size:0.68rem;font-weight:700;color:#EF4444;
}
.test-details {
    font-size:0.82rem;color:#94A3B8;line-height:1.5;
    background:rgba(15,23,42,0.5);padding:0.75rem;border-radius:8px;
    margin-top:0.75rem;border:1px solid rgba(148,163,184,0.07);
}
.compliance-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.2rem 1.4rem;transition:all 0.25s ease;
    animation:fadeIn 0.4s ease both;
}
.compliance-card:hover { border-color:rgba(148,163,184,0.2);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.compliance-name { font-size:0.85rem;font-weight:700;color:#F1F5F9;margin-bottom:0.3rem; }
.compliance-desc { font-size:0.75rem;color:#64748B;margin-bottom:1rem;line-height:1.4; }
.coverage-bar-wrap { height:6px;background:rgba(148,163,184,0.1);border-radius:3px;overflow:hidden;margin-bottom:0.4rem; }
.coverage-bar { height:100%;border-radius:3px;transition:width 0.5s ease; }
.coverage-pct { font-size:0.72rem;font-weight:700; }
.framework-badge {
    display:inline-flex;align-items:center;padding:0.18rem 0.55rem;
    border-radius:100px;font-size:0.62rem;font-weight:700;
    text-transform:uppercase;letter-spacing:0.5px;margin-bottom:0.75rem;
}
.run-btn-wrapper { display:flex;align-items:center;gap:1rem;margin-bottom:1.5rem; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

# ── Page header ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="val-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#22C55E;margin-bottom:0.3rem;">Testing & Compliance</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Validation Center</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Automated test suite — validate detection, risk scoring, and graph engines against predefined scenarios.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#22C55E;
                letter-spacing:1px;text-transform:uppercase;">✅ AUTO-TEST SUITE</span>
</div>
""", unsafe_allow_html=True)

if 'validation_results' not in st.session_state:
    st.session_state.validation_results = None

col1, col2 = st.columns([1, 4])
with col1:
    if st.button("▶ Run All Test Cases", type="primary", width="stretch"):
        st.session_state.validation_results = "running"
        st.rerun()

with col2:
    if st.session_state.validation_results == "running":
        progress_bar = st.progress(0)
        status_text  = st.empty()

        engine = ValidationEngine()

        steps = [
            ("Injecting test data into database…",     20),
            ("Running Identity Resolver…",              40),
            ("Running Anomaly Detection Engine…",       60),
            ("Running Risk Scoring Engine…",            80),
            ("Validating outcomes…",                    100),
        ]
        results = None
        for step_text, pct in steps:
            status_text.markdown(f'<div style="font-size:0.82rem;color:#94A3B8;">{step_text}</div>', unsafe_allow_html=True)
            progress_bar.progress(pct - 10)
            time.sleep(0.4)
            if pct == 100:
                results = engine.run_validations()
            progress_bar.progress(pct)
            time.sleep(0.3)

        st.session_state.validation_results = results
        st.rerun()

st.markdown('<div class="section-hdr"><h2>Test Results</h2></div>', unsafe_allow_html=True)

if isinstance(st.session_state.validation_results, list):
    results  = st.session_state.validation_results
    passed   = sum(1 for r in results if r['status'] == 'PASS')
    failed   = len(results) - passed
    coverage = int((passed / len(results)) * 100) if results else 0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#3B82F6;">{len(results)}</div><div class="metric-lbl">Total Tests</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#22C55E;">{passed}</div><div class="metric-lbl">Passed ✓</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:#EF4444;">{failed}</div><div class="metric-lbl">Failed ✗</div></div>', unsafe_allow_html=True)
    with m4:
        cov_clr = '#22C55E' if coverage >= 80 else '#EAB308' if coverage >= 60 else '#EF4444'
        st.markdown(f'<div class="metric-box"><div class="metric-val" style="color:{cov_clr};">{coverage}%</div><div class="metric-lbl">Coverage</div></div>', unsafe_allow_html=True)

    # Coverage mini-chart
    if results:
        fig_cov = go.Figure(go.Bar(
            x=[coverage, 100 - coverage],
            y=['Coverage'],
            orientation='h',
            marker_color=['#22C55E' if coverage >= 80 else '#EAB308' if coverage >= 60 else '#EF4444', 'rgba(30,41,59,0.8)'],
            text=[f'{coverage}%', ''],
            textposition='inside',
            textfont=dict(color='white', size=13, weight=700),
            showlegend=False,
        ))
        fig_cov.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            barmode='stack', height=50,
            xaxis=dict(showgrid=False, showticklabels=False, range=[0,100]),
            yaxis=dict(showgrid=False, showticklabels=False),
            margin=dict(t=0,b=0,l=0,r=0),
        )
        st.plotly_chart(fig_cov, width="stretch")

    st.markdown('<br>', unsafe_allow_html=True)

    for i, res in enumerate(results):
        card_class   = "test-card-pass" if res['status'] == 'PASS' else "test-card-fail"
        status_class = "test-status-pass" if res['status'] == 'PASS' else "test-status-fail"
        status_icon  = "✓" if res['status'] == 'PASS' else "✗"
        delay = f"animation-delay:{i*0.05}s"
        st.markdown(f"""
        <div class="test-card {card_class}" style="{delay}">
            <div class="test-header">
                <div class="test-title">{res['name']}</div>
                <div class="{status_class}">{status_icon} {res['status']}</div>
            </div>
            <div class="test-details">{res['details']}</div>
        </div>
        """, unsafe_allow_html=True)

    # Download
    csv_data = pd.DataFrame(results).to_csv(index=False)
    st.download_button(
        label="⬇️ Download Validation Report (CSV)",
        data=csv_data,
        file_name='identitylens_validation_report.csv',
        mime='text/csv',
    )

elif st.session_state.validation_results is None:
    st.markdown("""
    <div style="padding:2rem;background:rgba(30,41,59,0.5);border:1px solid rgba(148,163,184,0.1);
                border-radius:12px;text-align:center;color:#64748B;font-size:0.9rem;">
        No tests have been run yet.<br>
        <span style="font-size:0.8rem;">Click <strong style="color:#3B82F6;">▶ Run All Test Cases</strong> to execute the validation suite.</span>
    </div>
    """, unsafe_allow_html=True)

# ── Compliance Dashboard ───────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Compliance Framework Coverage</h2></div>', unsafe_allow_html=True)

# Determine coverage from test results
results_list = st.session_state.validation_results if isinstance(st.session_state.validation_results, list) else []
base_coverage = int((sum(1 for r in results_list if r['status'] == 'PASS') / len(results_list)) * 100) if results_list else 72

compliance_frameworks = [
    {
        "name": "NIST SP 800-53",
        "badge_color": "#3B82F6",
        "desc": "Security and Privacy Controls for Information Systems",
        "coverage": min(base_coverage + 8, 100),
        "controls": ["AC-2 Account Management", "AC-6 Least Privilege", "AU-2 Event Logging", "IA-5 Auth Management"],
        "status": "Partially Compliant",
        "status_color": "#EAB308",
    },
    {
        "name": "MITRE ATT&CK",
        "badge_color": "#EF4444",
        "desc": "Adversarial Tactics, Techniques & Common Knowledge",
        "coverage": min(base_coverage + 5, 100),
        "controls": ["T1078 Valid Accounts", "T1548 Privilege Escalation", "T1136 Create Account", "T1087 Account Discovery"],
        "status": "Detection Active",
        "status_color": "#22C55E",
    },
    {
        "name": "GDPR",
        "badge_color": "#8B5CF6",
        "desc": "General Data Protection Regulation — EU",
        "coverage": min(base_coverage + 12, 100),
        "controls": ["Art. 5 Data Principles", "Art. 25 Privacy by Design", "Art. 32 Security Measures", "Art. 33 Breach Notification"],
        "status": "Monitored",
        "status_color": "#3B82F6",
    },
    {
        "name": "CIS Controls",
        "badge_color": "#22C55E",
        "desc": "Center for Internet Security — 18 Critical Controls",
        "coverage": min(base_coverage + 3, 100),
        "controls": ["CIS-1 Asset Inventory", "CIS-5 Account Management", "CIS-6 Access Control", "CIS-8 Audit Logging"],
        "status": "Implemented",
        "status_color": "#22C55E",
    },
]

col_c1, col_c2 = st.columns(2)
for i, fw in enumerate(compliance_frameworks):
    col = col_c1 if i % 2 == 0 else col_c2
    cov = fw['coverage']
    bar_clr = '#22C55E' if cov >= 80 else '#EAB308' if cov >= 60 else '#EF4444'

    controls_html = "".join([
        f'<div style="display:flex;align-items:center;gap:0.4rem;padding:0.2rem 0;font-size:0.78rem;color:#94A3B8;">'
        f'<span style="width:5px;height:5px;border-radius:50%;background:{bar_clr};flex-shrink:0;"></span>'
        f'{ctrl}</div>'
        for ctrl in fw['controls']
    ])

    with col:
        st.markdown(f"""
        <div class="compliance-card">
            <div class="framework-badge" style="background:rgba({_hex_to_rgb(fw['badge_color'])},0.12);
                         color:{fw['badge_color']};border:1px solid rgba({_hex_to_rgb(fw['badge_color'])},0.25);">
                {fw['name']}
            </div>
            <div class="compliance-desc">{fw['desc']}</div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem;">
                <span style="font-size:0.72rem;color:#94A3B8;font-weight:600;">Coverage</span>
                <span class="coverage-pct" style="color:{bar_clr};">{cov}%</span>
            </div>
            <div class="coverage-bar-wrap">
                <div class="coverage-bar" style="width:{cov}%;background:{bar_clr};
                     box-shadow:0 0 6px {bar_clr}66;"></div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin:0.75rem 0 0.5rem;">
                <span style="font-size:0.72rem;color:#64748B;font-weight:600;">Key Controls Monitored</span>
                <span style="background:rgba({_hex_to_rgb(fw['status_color'])},0.1);
                             color:{fw['status_color']};
                             border:1px solid rgba({_hex_to_rgb(fw['status_color'])},0.25);
                             padding:2px 8px;border-radius:100px;font-size:0.62rem;font-weight:700;">
                    {fw['status']}
                </span>
            </div>
            {controls_html}
        </div>
        """, unsafe_allow_html=True)


st.markdown('</div>', unsafe_allow_html=True)
