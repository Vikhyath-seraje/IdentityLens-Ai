import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver

st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Dashboard</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Executive Overview</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Real-time identity security posture across all enterprise platforms.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,122,76,0.06);border:1px solid rgba(0,122,76,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#007A4C;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">● LIVE</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
@st.cache_data
def load_summary_data():
    resolver = IdentityResolver()
    return resolver.get_identity_summary()

@st.cache_data
def load_risk_data():
    engine = RiskEngine()
    return engine.calculate_risk_scores()

summary = load_summary_data()
risk_df = load_risk_data()

# ── KPI Metrics ────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🆔 Total Identities", summary['total_identities'], help="All identities across AD, AWS & Okta")
with col2:
    st.metric("🔗 Correlated (All 3)", summary['has_all_three_platforms'], help="Identities present on AD, AWS and Okta")
with col3:
    critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
    st.metric("🔴 Critical Risk", critical_count, delta=f"-{critical_count} to resolve", delta_color="inverse")
with col4:
    high_count = len(risk_df[risk_df['risk_level'] == 'High'])
    st.metric("🟠 High Risk", high_count, delta=f"-{high_count} to resolve", delta_color="inverse")

st.divider()

# ── Visualizations ─────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Threat Intelligence Charts</h2></div>', unsafe_allow_html=True)

col_charts_1, col_charts_2 = st.columns(2)

with col_charts_1:
    type_df = pd.DataFrame(list(summary['types'].items()), columns=['Type', 'Count'])
    fig_types = px.pie(
        type_df, values='Count', names='Type', hole=0.55,
        color_discrete_sequence=['#00d4ff', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444']
    )
    fig_types.update_layout(
        paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
        font_color='#1A1A1A', title='Identity Type Distribution',
        title_font_size=14, title_font_color='#1A1A1A',
        legend=dict(font=dict(color='#4A4A4A'), bgcolor='rgba(0,0,0,0)'),
        margin=dict(t=40, b=20),
    )
    fig_types.update_traces(textfont_color='white', textfont_size=12)
    st.plotly_chart(fig_types, use_container_width=True)

with col_charts_2:
    risk_counts = risk_df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    color_map = {'Critical': '#ef4444', 'High': '#f59e0b', 'Medium': '#eab308', 'Low': '#10b981'}
    fig_risk = px.bar(
        risk_counts, x='Risk Level', y='Count', color='Risk Level',
        color_discrete_map=color_map, text='Count'
    )
    fig_risk.update_layout(
        paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
        font_color='#1A1A1A', title='Risk Level Distribution',
        title_font_size=14, title_font_color='#1A1A1A',
        showlegend=False, xaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
        yaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
        margin=dict(t=40, b=20),
    )
    fig_risk.update_traces(textposition='outside', textfont_color='#1A1A1A',
                           marker_line_color='rgba(0,0,0,0)', marker_line_width=0)
    st.plotly_chart(fig_risk, use_container_width=True)

# ── Department breakdown ────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identities by Department</h2></div>', unsafe_allow_html=True)
dept_df = pd.DataFrame(list(summary['departments'].items()), columns=['Department', 'Count'])
dept_df = dept_df.sort_values('Count', ascending=True)
fig_dept = px.bar(
    dept_df, x='Count', y='Department', orientation='h',
    color='Count', color_continuous_scale='Blues',
    text='Count'
)
fig_dept.update_layout(
    paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
    font_color='#1A1A1A', height=350,
    showlegend=False, coloraxis_showscale=False,
    xaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
    yaxis=dict(gridcolor='rgba(255,255,255,0)', tickfont=dict(size=11, color='#4A4A4A')),
    margin=dict(t=10, b=20, l=10, r=20),
)
fig_dept.update_traces(textposition='outside', textfont_color='#1A1A1A',
                       marker_line_color='rgba(0,0,0,0)')
st.plotly_chart(fig_dept, use_container_width=True)

# ── Risk score gauge ───────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Overall Risk Posture</h2></div>', unsafe_allow_html=True)
col_g1, col_g2, col_g3 = st.columns([1, 2, 1])
with col_g2:
    avg_risk = round(risk_df['risk_score'].mean(), 1)
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=avg_risk,
        delta={'reference': 50, 'increasing': {'color': '#ef4444'}, 'decreasing': {'color': '#10b981'}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#64748b'},
            'bar': {'color': '#3b82f6'},
            'bgcolor': 'rgba(255,255,255,0.03)',
            'bordercolor': 'rgba(255,255,255,0.07)',
            'steps': [
                {'range': [0, 30],  'color': 'rgba(16,185,129,0.15)'},
                {'range': [30, 60], 'color': 'rgba(234,179,8,0.15)'},
                {'range': [60, 80], 'color': 'rgba(245,158,11,0.15)'},
                {'range': [80, 100],'color': 'rgba(239,68,68,0.15)'},
            ],
            'threshold': {'line': {'color': '#ef4444', 'width': 3}, 'value': 80}
        },
        title={'text': "Average Risk Score", 'font': {'color': '#94a3b8', 'size': 14}}
    ))
    fig_gauge.update_layout(
        paper_bgcolor='rgba(255,255,255,0)', font_color='#1A1A1A',
        height=280, margin=dict(t=30, b=20, l=30, r=30),
    )
    st.plotly_chart(fig_gauge, use_container_width=True)
