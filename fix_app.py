import os

filepath = 'c:/Users/vikhy/OneDrive/Desktop/SocGen Hackathon/app.py'
with open(filepath, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find where to cut (line 669 is the start of st.markdown(""" for login footer)
cut_idx = -1
for i, line in enumerate(lines):
    if 'st.error("Invalid credentials. Please try again.")' in line:
        cut_idx = i + 1
        break

if cut_idx != -1:
    good_lines = lines[:cut_idx]
    
    append_str = """
        st.markdown(\"\"\"
            </div>
            <div class="sg-login-footer">
                <strong>Demo credentials:</strong><br>
                <code>admin / admin123</code> &nbsp;|&nbsp;
                <code>analyst / analyst123</code> &nbsp;|&nbsp;
                <code>socgen / socgen2026</code><br><br>
                🔒 Protected by enterprise-grade security. All access is monitored and logged.
            </div>
        </div>
        </div>
        \"\"\", unsafe_allow_html=True)

    st.stop()

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATED APP
# ═══════════════════════════════════════════════════════════════════

@st.cache_data(ttl=300)
def load_identity_summary():
    from backend.identity_resolver import IdentityResolver
    return IdentityResolver().get_identity_summary()

@st.cache_data(ttl=300)
def load_risk_scores():
    from backend.risk_engine import RiskEngine
    return RiskEngine().calculate_risk_scores()

@st.cache_data(ttl=300)
def load_anomalies():
    from backend.anomaly_detection import AnomalyDetectionEngine
    return AnomalyDetectionEngine().detect_anomalies()

try:
    summary        = load_identity_summary()
    risk_df        = load_risk_scores()
    anomalies_df   = load_anomalies()
    critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
    high_count     = len(risk_df[risk_df['risk_level'] == 'High'])
    anomaly_count  = len(anomalies_df)
    avg_risk       = round(risk_df['risk_score'].mean(), 1)
    total_ids      = summary.get('total_identities', 0)
except Exception:
    critical_count = high_count = anomaly_count = avg_risk = total_ids = 0

user     = st.session_state.user
initials = "".join([n[0].upper() for n in user["name"].split()[:2]])

# ── Black utility bar ─────────────────────────────────────────────────────────
st.markdown(f\"\"\"
<div class="sg-utility-bar">
    <div class="sg-utility-left">
        <span class="sg-live-dot"></span>
        <span>Live Platform</span>
        <span style="opacity:0.35;">|</span>
        <span>IdentityLens AI v2.0</span>
    </div>
    <div class="sg-utility-right">
        <span class="sg-util-link">Documentation</span>
        <span class="sg-util-link">Support</span>
        <span style="opacity:0.35;">|</span>
        <span style="color:rgba(255,255,255,0.5);">© 2026 SocGen Hackathon</span>
    </div>
</div>
\"\"\", unsafe_allow_html=True)

# ── Navigation Definition (Must be defined BEFORE st.page_link) ───────────────
p1 = st.Page("views/1_Executive_Overview.py",     title="Executive Overview",    icon="📊")
p2 = st.Page("views/2_Identity_Explorer.py",      title="Identity Explorer",     icon="🔎")
p3 = st.Page("views/3_Risk_Center.py",            title="Risk Center",           icon="🎯")
p4 = st.Page("views/4_Anomaly_Detection.py",      title="Anomaly Detection",     icon="🚨")
p5 = st.Page("views/5_Attack_Graph.py",           title="Attack Graph",          icon="🕸️")
p6 = st.Page("views/6_AI_Remediation_Center.py",  title="AI Remediation",        icon="🤖")
p7 = st.Page("views/7_Quarantine_Center.py",      title="Quarantine Center",     icon="🛡️")
p8 = st.Page("views/8_Validation_Center.py",      title="Validation Center",     icon="✅")

pg = st.navigation([p1, p2, p3, p4, p5, p6, p7, p8], position="hidden")

# ── Native Streamlit Navbar ───────────────────────────────────────────────────
nav_cols = st.columns([3, 0.8, 0.8, 0.8, 0.8, 0.8, 1, 1, 1, 2], vertical_alignment="center")

with nav_cols[0]:
    st.markdown(\"\"\"
        <div class="sg-brand">
            <div class="sg-logo">
                <div class="sg-logo-box"><div class="sg-logo-box-inner"></div></div>
            </div>
            <div class="sg-brand-text">
                <div class="sg-brand-name">Société Générale</div>
                <div class="sg-brand-sub">IdentityLens AI Platform</div>
            </div>
        </div>
    \"\"\", unsafe_allow_html=True)

with nav_cols[1]: st.page_link(p1, label="Overview")
with nav_cols[2]: st.page_link(p2, label="Identity")
with nav_cols[3]: st.page_link(p3, label="Risk")
with nav_cols[4]: st.page_link(p4, label="Threats")
with nav_cols[5]: st.page_link(p5, label="Graph")
with nav_cols[6]: st.page_link(p6, label="Response")
with nav_cols[7]: st.page_link(p7, label="Quarantine")
with nav_cols[8]: st.page_link(p8, label="Validation")

with nav_cols[9]:
    st.markdown(f\"\"\"
        <div class="sg-user-chip">
            <div class="sg-user-avatar">{initials}</div>
            <span>{user['name']}</span>
        </div>
    \"\"\", unsafe_allow_html=True)

# ── Stats bar ─────────────────────────────────────────────────────────────────
critical_color = "red" if critical_count > 0 else "green"
high_color = "orange" if high_count > 0 else "green"

st.markdown(f\"\"\"
<div class="sg-stats-bar">
    <div class="sg-stat">
        <span class="sg-stat-label">Identities Monitored</span>
        <span class="sg-stat-value">{total_ids}</span>
    </div>
    <div class="sg-stat">
        <span class="sg-stat-label">Critical Risk</span>
        <span class="sg-stat-value {critical_color}">{critical_count}</span>
    </div>
    <div class="sg-stat">
        <span class="sg-stat-label">High Risk</span>
        <span class="sg-stat-value {high_color}">{high_count}</span>
    </div>
    <div class="sg-stat">
        <span class="sg-stat-label">Active Anomalies</span>
        <span class="sg-stat-value {'red' if anomaly_count > 0 else 'green'}">{anomaly_count}</span>
    </div>
    <div class="sg-stat">
        <span class="sg-stat-label">Avg Risk Score</span>
        <span class="sg-stat-value">{avg_risk}</span>
    </div>
    <div style="flex:1;"></div>
</div>
\"\"\", unsafe_allow_html=True)

# Run the page content
pg.run()

# Sign out in a tiny sidebar that's always collapsed
with st.sidebar:
    if st.button("🚪 Sign Out", use_container_width=True, key="signout"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()
"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(good_lines)
        f.write("\n")
        f.write(append_str)
    print("Fixed app.py")
else:
    print("Could not find cut index")
