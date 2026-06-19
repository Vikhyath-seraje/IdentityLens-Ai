import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
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

# ── Custom CSS for a polished look ───────────────────────────────────────────
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .main-header h1 {
        font-size: 2.4rem;
        margin: 0;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    .main-header p {
        opacity: 0.85;
        font-size: 1.1rem;
        margin-top: 0.3rem;
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
    }
    div[data-testid="stMetric"] label {
        color: #8892b0 !important;
        font-size: 0.85rem !important;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        color: #ccd6f6 !important;
        font-size: 2rem !important;
        font-weight: 700 !important;
    }

    /* Dataframe styling */
    .stDataFrame {
        border-radius: 12px;
        overflow: hidden;
    }

    /* Section headers */
    .section-header {
        color: #ccd6f6;
        border-left: 4px solid #64ffda;
        padding-left: 12px;
        margin-top: 1.5rem;
        margin-bottom: 0.8rem;
    }

    /* Risk badge styling */
    .risk-critical { color: #ff4444; font-weight: 700; }
    .risk-high { color: #ff8c00; font-weight: 700; }
    .risk-medium { color: #ffd700; font-weight: 600; }
    .risk-low { color: #00c851; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1>🔍 IdentityLens AI</h1>
    <p>Enterprise Identity Security Analytics Platform — Real-time risk intelligence across Active Directory, AWS IAM & Okta</p>
</div>
""", unsafe_allow_html=True)

# ── Data Loaders (cached) ───────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_identity_summary():
    resolver = IdentityResolver()
    return resolver.get_identity_summary()

@st.cache_data(ttl=300)
def load_resolved_identities():
    resolver = IdentityResolver()
    return resolver.get_resolved_identities()

@st.cache_data(ttl=300)
def load_risk_scores():
    engine = RiskEngine()
    return engine.calculate_risk_scores()

@st.cache_data(ttl=300)
def load_anomalies():
    engine = AnomalyDetectionEngine()
    return engine.detect_anomalies()

# ── Load all data ────────────────────────────────────────────────────────────
try:
    summary = load_identity_summary()
    identities_df = load_resolved_identities()
    risk_df = load_risk_scores()
    anomalies_df = load_anomalies()
except Exception as e:
    st.error(f"⚠️ Failed to load data. Make sure the database is initialized: `python database/init_db.py`\n\nError: {e}")
    st.stop()

# Merge risk with identity info for richer display
risk_merged = risk_df.merge(
    identities_df[['identity_id', 'name', 'department', 'type']],
    on='identity_id', how='left'
)

# ── KPI Row ──────────────────────────────────────────────────────────────────
st.markdown('<h3 class="section-header">Security Overview</h3>', unsafe_allow_html=True)

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
high_count = len(risk_df[risk_df['risk_level'] == 'High'])
anomaly_count = len(anomalies_df)
avg_risk = round(risk_df['risk_score'].mean(), 1)

kpi1.metric("Total Identities", summary['total_identities'])
kpi2.metric("Correlated (All 3)", summary['has_all_three_platforms'])
kpi3.metric("🔴 Critical Risk", critical_count)
kpi4.metric("🟠 High Risk", high_count)
kpi5.metric("⚠️ Anomalies", anomaly_count)

# ── Row 1: Risk Distribution + Identity Types ───────────────────────────────
st.markdown('<h3 class="section-header">Risk & Identity Analytics</h3>', unsafe_allow_html=True)

col_chart1, col_chart2, col_chart3 = st.columns(3)

with col_chart1:
    st.markdown("##### Risk Level Distribution")
    risk_counts = risk_df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    color_map = {'Critical': '#ff4444', 'High': '#ff8c00', 'Medium': '#ffd700', 'Low': '#00c851'}
    fig_risk = px.pie(
        risk_counts, values='Count', names='Risk Level',
        hole=0.45,
        color='Risk Level',
        color_discrete_map=color_map,
    )
    fig_risk.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#ccd6f6',
        margin=dict(t=30, b=10, l=10, r=10),
        height=320,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig_risk, use_container_width=True)

with col_chart2:
    st.markdown("##### Identity Types")
    type_df = pd.DataFrame(list(summary['types'].items()), columns=['Type', 'Count'])
    fig_types = px.pie(
        type_df, values='Count', names='Type',
        hole=0.45,
        color_discrete_sequence=['#64ffda', '#a78bfa', '#f472b6'],
    )
    fig_types.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#ccd6f6',
        margin=dict(t=30, b=10, l=10, r=10),
        height=320,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig_types, use_container_width=True)

with col_chart3:
    st.markdown("##### Risk Score Distribution")
    fig_hist = px.histogram(
        risk_df, x='risk_score', nbins=20,
        color_discrete_sequence=['#64ffda'],
    )
    fig_hist.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#ccd6f6',
        xaxis_title='Risk Score',
        yaxis_title='Count',
        margin=dict(t=30, b=40, l=40, r=10),
        height=320,
    )
    fig_hist.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
    fig_hist.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
    st.plotly_chart(fig_hist, use_container_width=True)

# ── Row 2: Departments + Anomaly Breakdown ───────────────────────────────────
col_dept, col_anom = st.columns(2)

with col_dept:
    st.markdown('<h3 class="section-header">Identities by Department</h3>', unsafe_allow_html=True)
    dept_df = pd.DataFrame(list(summary['departments'].items()), columns=['Department', 'Count'])
    dept_df = dept_df.sort_values('Count', ascending=True)
    fig_dept = px.bar(
        dept_df, x='Count', y='Department', orientation='h',
        color='Count',
        color_continuous_scale=['#1a1a2e', '#64ffda'],
    )
    fig_dept.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font_color='#ccd6f6',
        margin=dict(t=10, b=30, l=10, r=10),
        height=350,
        coloraxis_showscale=False,
    )
    fig_dept.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
    fig_dept.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
    st.plotly_chart(fig_dept, use_container_width=True)

with col_anom:
    st.markdown('<h3 class="section-header">Anomaly Breakdown</h3>', unsafe_allow_html=True)
    if not anomalies_df.empty:
        anom_counts = anomalies_df['anomaly_type'].value_counts().reset_index()
        anom_counts.columns = ['Anomaly Type', 'Count']
        fig_anom = px.bar(
            anom_counts, x='Count', y='Anomaly Type', orientation='h',
            color='Anomaly Type',
            color_discrete_sequence=['#ff4444', '#ff8c00', '#ffd700', '#a78bfa', '#f472b6'],
        )
        fig_anom.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#ccd6f6',
            margin=dict(t=10, b=30, l=10, r=10),
            height=350,
            showlegend=False,
        )
        fig_anom.update_xaxes(gridcolor='rgba(255,255,255,0.05)')
        fig_anom.update_yaxes(gridcolor='rgba(255,255,255,0.05)')
        st.plotly_chart(fig_anom, use_container_width=True)
    else:
        st.success("No anomalies detected — system is secure.")

# ── Row 3: Critical & High Risk Identities Table ────────────────────────────
st.markdown('<h3 class="section-header">🚨 Critical & High Risk Identities</h3>', unsafe_allow_html=True)

top_risks = risk_merged[risk_merged['risk_level'].isin(['Critical', 'High'])].sort_values('risk_score', ascending=False)

if not top_risks.empty:
    st.dataframe(
        top_risks[['identity_id', 'name', 'type', 'department', 'risk_score', 'risk_level', 'anomaly_count', 'privilege_count']].reset_index(drop=True),
        use_container_width=True,
        height=min(400, 40 + len(top_risks) * 35),
        column_config={
            'identity_id': st.column_config.TextColumn('Identity ID', width='small'),
            'name': st.column_config.TextColumn('Name', width='medium'),
            'type': st.column_config.TextColumn('Type', width='small'),
            'department': st.column_config.TextColumn('Dept', width='small'),
            'risk_score': st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=100, format='%d'),
            'risk_level': st.column_config.TextColumn('Level', width='small'),
            'anomaly_count': st.column_config.NumberColumn('Anomalies', width='small'),
            'privilege_count': st.column_config.NumberColumn('Privileges', width='small'),
        }
    )
else:
    st.success("No critical or high risk identities detected.")

# ── Row 4: Recent Anomalies Feed ────────────────────────────────────────────
st.markdown('<h3 class="section-header">📋 Recent Anomaly Feed</h3>', unsafe_allow_html=True)

if not anomalies_df.empty:
    # Merge anomaly data with identity names
    anomalies_display = anomalies_df.merge(
        identities_df[['identity_id', 'name', 'department']],
        on='identity_id', how='left'
    )
    st.dataframe(
        anomalies_display[['identity_id', 'name', 'department', 'anomaly_type', 'description']].head(20).reset_index(drop=True),
        use_container_width=True,
        height=min(400, 40 + min(20, len(anomalies_display)) * 35),
        column_config={
            'identity_id': st.column_config.TextColumn('Identity ID', width='small'),
            'name': st.column_config.TextColumn('Name', width='medium'),
            'department': st.column_config.TextColumn('Dept', width='small'),
            'anomaly_type': st.column_config.TextColumn('Type', width='medium'),
            'description': st.column_config.TextColumn('Description', width='large'),
        }
    )
else:
    st.success("No anomalies detected.")

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔍 IdentityLens AI")
    st.caption("Enterprise Identity Security")
    st.divider()
    st.markdown("**Quick Stats**")
    st.markdown(f"- 📊 **{summary['total_identities']}** identities monitored")
    st.markdown(f"- 🔴 **{critical_count}** critical risk")
    st.markdown(f"- 🟠 **{high_count}** high risk")
    st.markdown(f"- ⚠️ **{anomaly_count}** active anomalies")
    st.markdown(f"- 📈 Avg Risk Score: **{avg_risk}**")
    st.divider()
    st.markdown("**Modules**")
    st.markdown("""
    - 📊 Executive Overview
    - 🔎 Identity Explorer
    - 🎯 Risk Center
    - 🚨 Anomaly Detection
    - 🕸️ Attack Graph
    - 🤖 AI Remediation
    """)
    st.caption("👆 Use the page selector above to navigate")
    st.divider()
    st.caption("Powered by Gemini AI • Built for SocGen Hackathon 2026")
