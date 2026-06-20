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
                    color:#E60028;margin-bottom:0.3rem;">Risk Management</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Risk Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Comprehensive risk scoring and prioritised remediation intelligence.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(230,0,40,0.06);border:1px solid rgba(230,0,40,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#E60028;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">RISK ANALYSIS</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
@st.cache_data
def load_risk_data():
    engine = RiskEngine()
    risk_df = engine.calculate_risk_scores()
    resolver = IdentityResolver()
    identities_df = resolver.get_resolved_identities()
    return risk_df.merge(identities_df[['identity_id', 'name', 'department', 'type']], on='identity_id', how='left')

risk_df = load_risk_data()

# ── KPI Summary ────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🔴 Critical", len(risk_df[risk_df['risk_level'] == 'Critical']))
with col2:
    st.metric("🟠 High", len(risk_df[risk_df['risk_level'] == 'High']))
with col3:
    st.metric("🟡 Medium", len(risk_df[risk_df['risk_level'] == 'Medium']))
with col4:
    st.metric("🟢 Low", len(risk_df[risk_df['risk_level'] == 'Low']))

st.divider()

# ── Filters & Table ────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Risk Register</h2></div>', unsafe_allow_html=True)

col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
with col_f1:
    selected_level = st.selectbox("Risk Level", ['All', 'Critical', 'High', 'Medium', 'Low'])
with col_f2:
    departments = ['All'] + sorted(risk_df['department'].dropna().unique().tolist())
    selected_dept = st.selectbox("Department", departments)
with col_f3:
    search_name = st.text_input("🔍  Search by name or ID", placeholder="Filter identities…")

filtered_df = risk_df.copy()
if selected_level != 'All':
    filtered_df = filtered_df[filtered_df['risk_level'] == selected_level]
if selected_dept != 'All':
    filtered_df = filtered_df[filtered_df['department'] == selected_dept]
if search_name:
    filtered_df = filtered_df[
        filtered_df['name'].str.contains(search_name, case=False, na=False) |
        filtered_df['identity_id'].str.contains(search_name, case=False, na=False)
    ]

st.caption(f"Showing **{len(filtered_df)}** of **{len(risk_df)}** identities")

st.dataframe(
    filtered_df[['identity_id', 'name', 'department', 'type', 'risk_score', 'risk_level', 'anomaly_count', 'privilege_count']]
        .sort_values(by='risk_score', ascending=False),
    use_container_width=True,
    height=340,
    column_config={
        'identity_id':    st.column_config.TextColumn('Identity ID',     width='small'),
        'name':           st.column_config.TextColumn('Name',            width='medium'),
        'department':     st.column_config.TextColumn('Department',      width='medium'),
        'type':           st.column_config.TextColumn('Type',            width='small'),
        'risk_score':     st.column_config.ProgressColumn('Risk Score',  min_value=0, max_value=100, format='%d %%'),
        'risk_level':     st.column_config.TextColumn('Level',           width='small'),
        'anomaly_count':  st.column_config.NumberColumn('Anomalies',     width='small'),
        'privilege_count':st.column_config.NumberColumn('Privileges',    width='small'),
    }
)

st.divider()

# ── Charts ─────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Risk Analytics</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    color_map = {'Critical': '#ef4444', 'High': '#f59e0b', 'Medium': '#eab308', 'Low': '#10b981'}
    fig_hist = px.histogram(
        risk_df, x="risk_score", color="risk_level", nbins=25,
        color_discrete_map=color_map, opacity=0.85,
        title="Risk Score Distribution"
    )
    fig_hist.update_layout(
        paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
        font_color='#1A1A1A', title_font_color='#1A1A1A', title_font_size=14,
        legend=dict(font=dict(color='#4A4A4A'), bgcolor='rgba(0,0,0,0)'),
        xaxis=dict(gridcolor='rgba(0,0,0,0.07)', title='Risk Score'),
        yaxis=dict(gridcolor='rgba(0,0,0,0.07)', title='Count'),
        margin=dict(t=40, b=20),
        bargap=0.05,
    )
    st.plotly_chart(fig_hist, use_container_width=True)

with col_c2:
    dept_risk = risk_df.groupby('department')['risk_score'].mean().reset_index()
    dept_risk = dept_risk.sort_values('risk_score', ascending=True)
    fig_dept = px.bar(
        dept_risk, x='risk_score', y='department', orientation='h',
        color='risk_score', color_continuous_scale='RdYlGn_r',
        text=dept_risk['risk_score'].round(1), title="Avg Risk Score by Department"
    )
    fig_dept.update_layout(
        paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
        font_color='#1A1A1A', title_font_color='#1A1A1A', title_font_size=14,
        coloraxis_showscale=False, showlegend=False,
        xaxis=dict(gridcolor='rgba(0,0,0,0.07)', title='Avg Risk Score', range=[0, 100]),
        yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#4A4A4A')),
        margin=dict(t=40, b=20, l=10, r=30),
    )
    fig_dept.update_traces(textposition='outside', textfont_color='#1A1A1A')
    st.plotly_chart(fig_dept, use_container_width=True)

# ── Top 10 highest risk ────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Top 10 Highest-Risk Identities</h2></div>', unsafe_allow_html=True)
top10 = risk_df.nlargest(10, 'risk_score')
fig_top = go.Figure(go.Bar(
    x=top10['risk_score'],
    y=top10['name'].fillna(top10['identity_id']),
    orientation='h',
    text=top10['risk_score'].round(1),
    textposition='outside',
    marker=dict(
        color=top10['risk_score'],
        colorscale='RdYlGn_r',
        cmin=0, cmax=100,
        line=dict(color='rgba(0,0,0,0)'),
    )
))
fig_top.update_layout(
    paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
    font_color='#1A1A1A', height=340,
    xaxis=dict(gridcolor='rgba(0,0,0,0.07)', range=[0, 115], title='Risk Score'),
    yaxis=dict(gridcolor='rgba(0,0,0,0)', autorange='reversed'),
    margin=dict(t=10, b=20, l=10, r=40),
)
fig_top.update_traces(textfont_color='#1A1A1A')
st.plotly_chart(fig_top, use_container_width=True)
