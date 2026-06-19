import streamlit as st
import pandas as pd
import sqlite3
import sys
import os

# Ensure the project root is on the path so backend imports work
sys.path.insert(0, os.path.dirname(__file__))

from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine
from backend.anomaly_detection import AnomalyDetectionEngine

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="IdentityLens AI",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .main-header h1 { font-size: 2.4rem; margin: 0; font-weight: 700; letter-spacing: -0.5px; }
    .main-header p  { opacity: 0.85; font-size: 1.1rem; margin-top: 0.3rem; }

    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    div[data-testid="stMetric"] label { color: #8892b0 !important; font-size: 0.85rem !important; }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #ccd6f6 !important; font-size: 2rem !important; font-weight: 700 !important;
    }

    .stDataFrame { border-radius: 12px; overflow: hidden; }

    .section-header {
        color: #ccd6f6;
        border-left: 4px solid #64ffda;
        padding-left: 12px;
        margin-top: 1.5rem;
        margin-bottom: 0.8rem;
    }

    .risk-critical { color: #ff4444; font-weight: 700; }
    .risk-high     { color: #ff8c00; font-weight: 700; }
    .risk-medium   { color: #ffd700; font-weight: 600; }
    .risk-low      { color: #00c851; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ── Data Loaders for Sidebar ──────────────────────────────────────────────────
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
    summary = load_identity_summary()
    risk_df = load_risk_scores()
    anomalies_df = load_anomalies()
    
    critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
    high_count     = len(risk_df[risk_df['risk_level'] == 'High'])
    anomaly_count  = len(anomalies_df)
    avg_risk       = round(risk_df['risk_score'].mean(), 1)
except Exception as e:
    summary = {'total_identities': 0}
    critical_count = high_count = anomaly_count = avg_risk = 0

# ── Define Navigation Pages ──────────────────────────────────────────────────
pg = st.navigation([
    st.Page("pages/1_Executive_Overview.py", title="Executive Overview", icon="📊"),
    st.Page("pages/2_Identity_Explorer.py", title="Identity Explorer", icon="🔎"),
    st.Page("pages/3_Risk_Center.py", title="Risk Center", icon="🎯"),
    st.Page("pages/4_Anomaly_Detection.py", title="Anomaly Detection", icon="🚨"),
    st.Page("pages/5_Attack_Graph.py", title="Attack Graph", icon="🕸️"),
    st.Page("pages/6_AI_Remediation_Center.py", title="AI Remediation", icon="🤖"),
    st.Page("pages/7_Quarantine_Center.py", title="Quarantine Center", icon="🛡️"),
    st.Page("pages/8_Infrastructure_Manager.py", title="Infrastructure Manager", icon="🏗️"),
])

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔍 IdentityLens AI")
    st.caption("Enterprise Identity Security")
    st.divider()
    st.markdown("**Quick Stats**")
    st.markdown(f"- 📊 **{summary.get('total_identities', 0)}** identities monitored")
    st.markdown(f"- 🔴 **{critical_count}** critical risk")
    st.markdown(f"- 🟠 **{high_count}** high risk")
    st.markdown(f"- ⚠️ **{anomaly_count}** active anomalies")
    st.markdown(f"- 📈 Avg Risk Score: **{avg_risk}**")
    st.divider()
    st.caption("Powered by Gemini AI • Built for SocGen Hackathon 2026")

# ── Run Current Page ──────────────────────────────────────────────────────────
pg.run()
