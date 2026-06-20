import streamlit as st
import sys, os

sys.path.insert(0, os.path.dirname(__file__))

from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine
from backend.anomaly_detection import AnomalyDetectionEngine

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IdentityLens AI — SocGen Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── SocGen-Inspired Master CSS ────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');

/* ─── Variables (SocGen palette) ───────── */
:root {
    --sg-red:        #E60028;
    --sg-red-dark:   #B3001F;
    --sg-red-light:  #FF1A3E;
    --sg-black:      #1A1A1A;
    --sg-dark:       #2D2D2D;
    --sg-grey-dark:  #4A4A4A;
    --sg-grey:       #6B6B6B;
    --sg-grey-mid:   #9E9E9E;
    --sg-grey-light: #D9D9D9;
    --sg-bg:         #F4F5F6;
    --sg-white:      #FFFFFF;
    --sg-border:     #E0E0E0;
    --sg-success:    #007A4C;
    --sg-warning:    #C97D00;
    --sg-info:       #0060A8;
    --radius:        4px;
    --radius-md:     8px;
    --shadow:        0 1px 4px rgba(0,0,0,0.08);
    --shadow-md:     0 4px 16px rgba(0,0,0,0.1);
}

/* ─── Reset / Font ─────────────────────── */
*, *::before, *::after { box-sizing: border-box; }
html, body, [class*="css"], .stApp {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important;
    background: var(--sg-bg) !important;
    color: var(--sg-black) !important;
}

/* ─── Hide all Streamlit chrome ─────────── */
#MainMenu, footer, header,
[data-testid="stToolbar"],
[data-testid="collapsedControl"],
[data-testid="stSidebarCollapseButton"],
[data-testid="stSidebar"] {
    visibility: hidden !important;
    height: 0 !important;
    display: none !important;
    width: 0 !important;
}

/* ─── Layout ────────────────────────────── */
.stApp { background: var(--sg-bg) !important; }
.main .block-container {
    padding: 0 !important;
    max-width: 100% !important;
}

/* ─── TOP UTILITY BAR ───────────────────── */
.sg-utility-bar {
    background: var(--sg-black);
    padding: 0 2.5rem;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.72rem;
    color: rgba(255,255,255,0.6);
}
.sg-utility-left { display: flex; align-items: center; gap: 1rem; }
.sg-utility-right { display: flex; align-items: center; gap: 1.5rem; }
.sg-util-link {
    color: rgba(255,255,255,0.6);
    text-decoration: none;
    font-size: 0.72rem;
    letter-spacing: 0.3px;
    cursor: pointer;
    transition: color 0.15s;
}
.sg-util-link:hover { color: white; }
.sg-live-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #4ade80;
    display: inline-block;
    animation: blink 2s infinite;
}
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

.sg-brand {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-shrink: 0;
    padding-left: 2.5rem;
}
.sg-logo {
    display: flex;
    align-items: center;
    gap: 0;
}
.sg-logo-box {
    width: 52px; height: 40px;
    background: var(--sg-red);
    display: grid;
    place-items: center;
    flex-shrink: 0;
}
.sg-logo-box-inner {
    width: 36px; height: 6px;
    background: white;
}
.sg-brand-text {
    padding: 0 0 0 0.75rem;
    border-left: 3px solid var(--sg-red);
}
.sg-brand-name {
    font-size: 0.82rem;
    font-weight: 800;
    color: var(--sg-black);
    letter-spacing: 0.5px;
    line-height: 1.1;
    text-transform: uppercase;
}
.sg-brand-sub {
    font-size: 0.65rem;
    color: var(--sg-grey);
    font-weight: 400;
    letter-spacing: 0.3px;
}

/* NATIVE NAVBAR (Streamlit Columns) */
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .sg-brand) {
    background: var(--sg-white);
    border-bottom: 1px solid var(--sg-border);
    box-shadow: var(--shadow);
    padding: 0;
    height: 72px;
    align-items: center;
    margin-bottom: 0;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .sg-brand) > [data-testid="column"] {
    display: flex;
    align-items: center;
    justify-content: center;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .sg-brand) > [data-testid="column"]:first-child {
    justify-content: flex-start;
}
[data-testid="stHorizontalBlock"]:has(> [data-testid="column"] .sg-brand) > [data-testid="column"]:last-child {
    justify-content: flex-end;
    padding-right: 2.5rem;
}

[data-testid="stPageLink-NavLink"] {
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    height: 72px !important;
    text-decoration: none !important;
    color: var(--sg-dark) !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    border-bottom: 3px solid transparent !important;
    border-radius: 0 !important;
    background: transparent !important;
    padding: 0 !important;
    margin: 0 !important;
    width: 100% !important;
    transition: all 0.15s ease !important;
}
[data-testid="stPageLink-NavLink"]:hover {
    color: var(--sg-red) !important;
    border-bottom-color: var(--sg-red) !important;
    background: transparent !important;
}
[data-testid="stPageLink-NavLink"][data-active="true"],
[data-testid="stPageLink-NavLink"][aria-current="page"] {
    color: var(--sg-red) !important;
    font-weight: 600 !important;
    border-bottom-color: var(--sg-red) !important;
}

.sg-user-chip {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0.8rem;
    border: 1px solid var(--sg-border);
    border-radius: 100px;
    font-size: 0.78rem;
    color: var(--sg-dark);
    cursor: pointer;
    transition: all 0.15s;
}
.sg-user-chip:hover {
    border-color: var(--sg-red);
    color: var(--sg-red);
}
.sg-user-avatar {
    width: 24px; height: 24px;
    background: var(--sg-red);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.65rem; font-weight: 700; color: white;
    flex-shrink: 0;
}
.sg-signout-btn {
    background: var(--sg-red);
    color: white;
    border: none;
    padding: 0.4rem 1rem;
    border-radius: var(--radius);
    font-size: 0.78rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    letter-spacing: 0.2px;
    text-decoration: none;
}
.sg-signout-btn:hover { background: var(--sg-red-dark); }

/* ─── SECONDARY NAV (stats bar) ─────────── */
.sg-stats-bar {
    background: var(--sg-white);
    border-bottom: 1px solid var(--sg-border);
    padding: 0.6rem 2.5rem;
    display: flex;
    align-items: center;
    gap: 0;
}
.sg-stat {
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0 1.5rem 0 0;
    margin-right: 1.5rem;
    border-right: 1px solid var(--sg-border);
    font-size: 0.8rem;
}
.sg-stat:last-of-type { border-right: none; }
.sg-stat-label { color: var(--sg-grey); font-weight: 400; }
.sg-stat-value { color: var(--sg-black); font-weight: 700; }
.sg-stat-value.red { color: var(--sg-red); }
.sg-stat-value.orange { color: var(--sg-warning); }
.sg-stat-value.green { color: var(--sg-success); }

/* ─── PAGE CONTENT ──────────────────────── */
.sg-page {
    padding: 2rem 2.5rem 3rem;
    max-width: 1440px;
    margin: 0 auto;
}
.sg-page-header {
    display: flex; align-items: flex-start; justify-content: space-between;
    flex-wrap: wrap; gap: 1rem;
    margin-bottom: 1.8rem;
    padding-bottom: 1.2rem;
    border-bottom: 1px solid var(--sg-border);
}
.sg-page-eyebrow {
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 1.2px; color: var(--sg-red); margin-bottom: 0.3rem;
}
.sg-page-title {
    font-size: 1.55rem; font-weight: 800; color: var(--sg-black);
    letter-spacing: -0.3px; margin: 0 0 0.25rem;
    line-height: 1.2;
}
.sg-page-desc {
    font-size: 0.875rem; color: var(--sg-grey); margin: 0; font-weight: 400;
}
.sg-page-badge {
    display: inline-flex; align-items: center;
    padding: 0.25rem 0.75rem;
    background: rgba(230,0,40,0.06);
    border: 1px solid rgba(230,0,40,0.2);
    border-radius: 100px;
    font-size: 0.68rem; font-weight: 700; color: var(--sg-red);
    letter-spacing: 0.8px; text-transform: uppercase;
    margin-top: 0.2rem; flex-shrink: 0;
}

/* ─── METRIC CARDS ──────────────────────── */
div[data-testid="stMetric"] {
    background: var(--sg-white) !important;
    border: 1px solid var(--sg-border) !important;
    border-radius: var(--radius-md) !important;
    padding: 1.2rem 1.4rem !important;
    box-shadow: var(--shadow) !important;
    transition: box-shadow 0.2s ease !important;
    position: relative; overflow: hidden;
}
div[data-testid="stMetric"]::before {
    content: '';
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    background: var(--sg-red);
}
div[data-testid="stMetric"]:hover {
    box-shadow: var(--shadow-md) !important;
}
div[data-testid="stMetric"] label {
    color: var(--sg-grey) !important;
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    letter-spacing: 0.8px !important;
    text-transform: uppercase !important;
}
div[data-testid="stMetricValue"] {
    color: var(--sg-black) !important;
    font-size: 1.9rem !important;
    font-weight: 800 !important;
    letter-spacing: -1px !important;
}
div[data-testid="stMetricDelta"] { font-size: 0.78rem !important; }

/* ─── SECTION HEADERS ───────────────────── */
.sg-section {
    display: flex; align-items: center; gap: 0.75rem;
    margin: 2rem 0 1rem;
}
.sg-section h2 {
    font-size: 1.05rem !important; font-weight: 700 !important;
    color: var(--sg-black) !important; margin: 0 !important;
}
.sg-section::after {
    content: ''; flex: 1; height: 1px; background: var(--sg-border);
}

/* ─── CARDS ─────────────────────────────── */
.sg-card {
    background: var(--sg-white);
    border: 1px solid var(--sg-border);
    border-radius: var(--radius-md);
    padding: 1.25rem 1.4rem;
    box-shadow: var(--shadow);
    transition: box-shadow 0.2s;
}
.sg-card:hover { box-shadow: var(--shadow-md); }
.sg-card-label {
    font-size: 0.68rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1px; color: var(--sg-grey); margin-bottom: 0.6rem;
}

/* ─── BADGES ─────────────────────────────── */
.badge {
    display: inline-block; padding: 0.18rem 0.55rem;
    border-radius: 100px; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.3px;
}
.badge-critical { background:rgba(230,0,40,.08);  color:#E60028; border:1px solid rgba(230,0,40,.2); }
.badge-high     { background:rgba(201,125,0,.08); color:#C97D00; border:1px solid rgba(201,125,0,.2); }
.badge-medium   { background:rgba(234,179,8,.08); color:#927000; border:1px solid rgba(234,179,8,.3); }
.badge-low      { background:rgba(0,122,76,.08);  color:#007A4C; border:1px solid rgba(0,122,76,.2); }
.badge-info     { background:rgba(0,96,168,.08);  color:#0060A8; border:1px solid rgba(0,96,168,.2); }

/* ─── TABLES ────────────────────────────── */
.stDataFrame {
    border-radius: var(--radius-md) !important;
    overflow: hidden !important;
    border: 1px solid var(--sg-border) !important;
    box-shadow: var(--shadow) !important;
}

/* ─── BUTTONS ───────────────────────────── */
.stButton > button {
    border-radius: var(--radius) !important;
    font-weight: 600 !important;
    font-size: 0.825rem !important;
    letter-spacing: 0.2px !important;
    transition: all 0.15s ease !important;
}
.stButton > button[kind="primary"] {
    background: var(--sg-red) !important;
    color: white !important;
    border: none !important;
    box-shadow: none !important;
}
.stButton > button[kind="primary"]:hover {
    background: var(--sg-red-dark) !important;
}
.stButton > button[kind="secondary"] {
    background: white !important;
    border: 1.5px solid var(--sg-border) !important;
    color: var(--sg-dark) !important;
}
.stButton > button[kind="secondary"]:hover {
    border-color: var(--sg-red) !important;
    color: var(--sg-red) !important;
}

/* ─── INPUTS ────────────────────────────── */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stMultiSelect > div > div {
    background: var(--sg-white) !important;
    border: 1.5px solid var(--sg-border) !important;
    border-radius: var(--radius) !important;
    color: var(--sg-black) !important;
    font-size: 0.875rem !important;
    box-shadow: none !important;
}
.stTextInput > div > div > input:focus {
    border-color: var(--sg-red) !important;
    box-shadow: 0 0 0 3px rgba(230,0,40,0.08) !important;
}

/* ─── TABS ──────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    background: var(--sg-white) !important;
    border: 1px solid var(--sg-border) !important;
    border-radius: var(--radius) !important;
    padding: 3px !important;
    gap: 2px !important;
    width: fit-content !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border-radius: 3px !important;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    color: var(--sg-grey) !important;
    padding: 0.35rem 1rem !important;
}
.stTabs [aria-selected="true"] {
    background: var(--sg-red) !important;
    color: white !important;
    font-weight: 600 !important;
}

/* ─── Expander ──────────────────────────── */
[data-testid="stExpander"] {
    background: var(--sg-white) !important;
    border: 1px solid var(--sg-border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow) !important;
}

/* ─── Divider ───────────────────────────── */
hr, .stDivider hr {
    border: none !important;
    height: 1px !important;
    background: var(--sg-border) !important;
    margin: 1.5rem 0 !important;
}

/* ─── Alerts ────────────────────────────── */
.stAlert { border-radius: var(--radius) !important; }

/* ─── Scrollbar ─────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--sg-bg); }
::-webkit-scrollbar-thumb { background: var(--sg-grey-light); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--sg-red); }

/* ─── LOGIN ─────────────────────────────── */
.sg-login-wrap {
    min-height: 100vh;
    background: var(--sg-bg);
    display: flex; flex-direction: column;
}
.sg-login-topbar {
    background: var(--sg-black);
    height: 36px;
    display: flex; align-items: center;
    padding: 0 2.5rem;
    font-size: 0.72rem;
    color: rgba(255,255,255,0.5);
    justify-content: space-between;
}
.sg-login-navbar {
    background: var(--sg-white);
    border-bottom: 1px solid var(--sg-border);
    padding: 0 2.5rem;
    height: 72px;
    display: flex; align-items: center;
    box-shadow: var(--shadow);
}
.sg-login-body {
    flex: 1;
    display: flex; align-items: center; justify-content: center;
    padding: 3rem 2rem;
}
.sg-login-card {
    background: var(--sg-white);
    border: 1px solid var(--sg-border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    width: 100%; max-width: 440px;
    overflow: hidden;
}
.sg-login-card-header {
    background: var(--sg-red);
    padding: 1.5rem 2rem;
    color: white;
}
.sg-login-card-title {
    font-size: 1.25rem; font-weight: 800; margin: 0 0 0.3rem; color: white;
    letter-spacing: -0.3px;
}
.sg-login-card-sub {
    font-size: 0.8rem; color: rgba(255,255,255,0.8); margin: 0;
}
.sg-login-card-body { padding: 2rem; }
.sg-login-footer {
    background: var(--sg-bg);
    border-top: 1px solid var(--sg-border);
    padding: 1rem 2rem;
    font-size: 0.72rem; color: var(--sg-grey); text-align: center; line-height: 1.6;
}
.sg-login-feature-list {
    display: flex; flex-direction: column; gap: 0.75rem;
    margin: 2rem 0 0;
    max-width: 480px;
}
.sg-login-feat {
    display: flex; align-items: flex-start; gap: 0.75rem;
}
.sg-login-feat-dot {
    width: 20px; height: 20px;
    background: var(--sg-red);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.6rem; color: white; font-weight: 700;
    flex-shrink: 0; margin-top: 0.1rem;
}
.sg-login-feat-text strong {
    display: block; font-size: 0.825rem; color: var(--sg-black); font-weight: 600;
}
.sg-login-feat-text span {
    font-size: 0.78rem; color: var(--sg-grey);
}
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════
VALID_USERS = {
    "admin":   {"password": "admin123",   "name": "Admin User",       "role": "Administrator"},
    "analyst": {"password": "analyst123", "name": "Security Analyst", "role": "SOC Analyst"},
    "socgen":  {"password": "socgen2026", "name": "SocGen Demo",      "role": "Viewer"},
}

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.user = None

# ── LOGIN PAGE ────────────────────────────────────────────────────────────────
if not st.session_state.authenticated:
    # Black utility bar
    st.markdown("""
    <div class="sg-login-topbar">
        <div style="display:flex;align-items:center;gap:1rem;">
            <span class="sg-live-dot"></span>
            <span>Secure Enterprise Portal</span>
        </div>
        <div style="display:flex;align-items:center;gap:1.5rem;">
            <span>Support</span>
            <span>Privacy Policy</span>
            <span>© 2026 SocGen Hackathon</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # White navbar with SocGen logo
    st.markdown("""
    <div class="sg-login-navbar">
        <div class="sg-brand">
            <div class="sg-logo">
                <div class="sg-logo-box"><div class="sg-logo-box-inner"></div></div>
            </div>
            <div class="sg-brand-text">
                <div class="sg-brand-name">Société Générale</div>
                <div class="sg-brand-sub">IdentityLens AI Platform</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Body: left feature column + right login card
    col_features, col_gap, col_login = st.columns([1.1, 0.15, 0.9])

    with col_features:
        st.markdown("""
        <div style="padding:3rem 0 2rem;">
            <div style="font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                        color:var(--sg-red);margin-bottom:1rem;">Enterprise Security Platform</div>
            <h1 style="font-size:2.2rem;font-weight:900;color:var(--sg-black);line-height:1.15;
                        letter-spacing:-0.8px;margin:0 0 1rem;">
                Identity Intelligence<br>
                <span style="color:var(--sg-red);">for the Modern SOC</span>
            </h1>
            <p style="font-size:0.95rem;color:var(--sg-grey);margin:0 0 2.5rem;line-height:1.7;max-width:420px;">
                Real-time visibility into enterprise identities across Active Directory,
                AWS IAM, and Okta — powered by Gemini AI.
            </p>
            <div class="sg-login-feature-list">
                <div class="sg-login-feat">
                    <div class="sg-login-feat-dot">1</div>
                    <div class="sg-login-feat-text">
                        <strong>360° Identity Correlation</strong>
                        <span>Unified view across all platforms in real time</span>
                    </div>
                </div>
                <div class="sg-login-feat">
                    <div class="sg-login-feat-dot">2</div>
                    <div class="sg-login-feat-text">
                        <strong>AI-Powered Anomaly Detection</strong>
                        <span>ML + rule engine detecting behavioural threats</span>
                    </div>
                </div>
                <div class="sg-login-feat">
                    <div class="sg-login-feat-dot">3</div>
                    <div class="sg-login-feat-text">
                        <strong>Automated Quarantine & Remediation</strong>
                        <span>Instant isolation with Gemini AI remediation plans</span>
                    </div>
                </div>
                <div class="sg-login-feat">
                    <div class="sg-login-feat-dot">4</div>
                    <div class="sg-login-feat-text">
                        <strong>Terraform IaC Management</strong>
                        <span>Full AWS infrastructure lifecycle from one panel</span>
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_login:
        st.markdown("""
        <div style="padding:3rem 0 2rem;">
        <div class="sg-login-card">
            <div class="sg-login-card-header">
                <div class="sg-login-card-title">Sign In</div>
                <div class="sg-login-card-sub">Access the IdentityLens AI Platform</div>
            </div>
            <div class="sg-login-card-body">
        """, unsafe_allow_html=True)

        username = st.text_input("Username", placeholder="Enter your username", key="login_user",
                                  label_visibility="visible")
        password = st.text_input("Password", placeholder="Enter your password",
                                  type="password", key="login_pass",
                                  label_visibility="visible")

        if st.button("Sign In →", type="primary", use_container_width=True, key="login_btn"):
            if username in VALID_USERS and VALID_USERS[username]["password"] == password:
                st.session_state.authenticated = True
                st.session_state.user = {"username": username, **VALID_USERS[username]}
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")

        st.markdown("""
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
        """, unsafe_allow_html=True)

    st.stop()

# ═══════════════════════════════════════════════════════════════════
# AUTHENTICATED APP
# ═══════════════════════════════════════════════════════════════════

@st.cache_data(ttl=300)
def load_identity_summary():
    return IdentityResolver().get_identity_summary()

@st.cache_data(ttl=300)
def load_risk_scores():
    return RiskEngine().calculate_risk_scores()

@st.cache_data(ttl=300)
def load_anomalies():
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
st.markdown(f"""
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
""", unsafe_allow_html=True)

# ── Navigation Definition (Must be defined BEFORE st.page_link) ───────────────
p1 = st.Page("views/1_Executive_Overview.py",     title="Executive Overview",    icon="📊")
p2 = st.Page("views/2_Identity_Explorer.py",      title="Identity Explorer",     icon="🔎")
p3 = st.Page("views/3_Risk_Center.py",            title="Risk Center",           icon="🎯")
p4 = st.Page("views/4_Anomaly_Detection.py",      title="Anomaly Detection",     icon="🚨")
p5 = st.Page("views/5_Attack_Graph.py",           title="Attack Graph",          icon="🕸️")
p6 = st.Page("views/6_AI_Remediation_Center.py",  title="AI Remediation",        icon="🤖")
p7 = st.Page("views/7_Quarantine_Center.py",      title="Quarantine Center",     icon="🛡️")

pg = st.navigation([p1, p2, p3, p4, p5, p6, p7], position="hidden")

# ── Native Streamlit Navbar ───────────────────────────────────────────────────
nav_cols = st.columns([3, 0.8, 0.8, 0.8, 0.8, 0.8, 1, 1, 2], vertical_alignment="center")

with nav_cols[0]:
    st.markdown("""
        <div class="sg-brand">
            <div class="sg-logo">
                <div class="sg-logo-box"><div class="sg-logo-box-inner"></div></div>
            </div>
            <div class="sg-brand-text">
                <div class="sg-brand-name">Société Générale</div>
                <div class="sg-brand-sub">IdentityLens AI Platform</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

with nav_cols[1]: st.page_link(p1, label="Overview")
with nav_cols[2]: st.page_link(p2, label="Identity")
with nav_cols[3]: st.page_link(p3, label="Risk")
with nav_cols[4]: st.page_link(p4, label="Threats")
with nav_cols[5]: st.page_link(p5, label="Graph")
with nav_cols[6]: st.page_link(p6, label="Response")
with nav_cols[7]: st.page_link(p7, label="Quarantine")

with nav_cols[8]:
    st.markdown(f"""
        <div class="sg-user-chip">
            <div class="sg-user-avatar">{initials}</div>
            <span>{user['name']}</span>
        </div>
    """, unsafe_allow_html=True)

# ── Stats bar ─────────────────────────────────────────────────────────────────
critical_color = "red" if critical_count > 0 else "green"
high_color = "orange" if high_count > 0 else "green"

st.markdown(f"""
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
""", unsafe_allow_html=True)

# Run the page content
pg.run()

# Sign out in a tiny sidebar that's always collapsed
with st.sidebar:
    if st.button("🚪 Sign Out", use_container_width=True, key="signout"):
        st.session_state.authenticated = False
        st.session_state.user = None
        st.rerun()

pg.run()
