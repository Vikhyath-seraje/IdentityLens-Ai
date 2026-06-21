import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver
from backend.anomaly_detection import AnomalyDetectionEngine, MITRE_MAPPING, get_mitre_mapping

# ── Dark Chart Theme ───────────────────────────────────────────────────────────
DARK_BG    = '#0F172A'
CARD_BG    = '#1E293B'
GRID_COLOR = 'rgba(148,163,184,0.08)'
TEXT_COLOR = '#94A3B8'
FONT_FAM   = 'Inter, sans-serif'
DARK_LAYOUT = dict(
    paper_bgcolor=DARK_BG,
    plot_bgcolor=CARD_BG,
    font=dict(family=FONT_FAM, color=TEXT_COLOR),
    title_font=dict(size=13, color='#F1F5F9', family=FONT_FAM),
)

COLOR_MAP = {
    'Critical': '#EF4444',
    'High':     '#F97316',
    'Medium':   '#EAB308',
    'Low':      '#22C55E',
}

# ── Page CSS ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@keyframes countUp {
    from { opacity:0; transform:translateY(6px); }
    to   { opacity:1; transform:translateY(0); }
}
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 0.85rem;
    margin-bottom: 1.5rem;
}
.exec-kpi {
    background: rgba(30,41,59,0.8);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(148,163,184,0.12);
    border-radius: 12px;
    padding: 1.1rem 1.2rem;
    position: relative; overflow: hidden;
    transition: all 0.3s ease;
    animation: countUp 0.5s ease both;
}
.exec-kpi:hover {
    border-color: rgba(148,163,184,0.22);
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.exec-kpi .stripe {
    position: absolute; left: 0; top: 0; bottom: 0;
    width: 3px; border-radius: 3px 0 0 3px;
}
.exec-kpi .glow {
    position: absolute; right: -10px; bottom: -10px;
    width: 70px; height: 70px; border-radius: 50%;
    opacity: 0.06;
}
.exec-kpi .kpi-icon-bg {
    position: absolute; right: 0.9rem; top: 0.9rem;
    font-size: 1.4rem; opacity: 0.25;
}
.exec-kpi .kpi-lbl {
    font-size: 0.6rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1.2px; color: #64748B; margin-bottom: 0.45rem;
}
.exec-kpi .kpi-val {
    font-size: 1.9rem; font-weight: 900; letter-spacing: -1px; line-height: 1;
    animation: countUp 0.6s ease both;
}
.exec-kpi .kpi-sub {
    font-size: 0.65rem; color: #64748B; margin-top: 0.4rem; line-height: 1.4;
}
.section-hdr {
    display: flex; align-items: center; gap: 0.75rem;
    margin: 1.75rem 0 1rem;
}
.section-hdr h2 {
    font-size: 0.82rem !important; font-weight: 700 !important;
    color: #F1F5F9 !important; margin: 0 !important;
    text-transform: uppercase; letter-spacing: 0.8px;
}
.section-hdr::after {
    content: ''; flex: 1; height: 1px; background: rgba(148,163,184,0.1);
}
.chart-wrapper {
    background: rgba(30,41,59,0.8);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(148,163,184,0.1);
    border-radius: 12px;
    padding: 1rem 1rem 0.5rem;
    transition: all 0.25s ease;
    animation: countUp 0.5s ease both;
}
.chart-wrapper:hover {
    border-color: rgba(148,163,184,0.18);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.chart-wrapper .chart-hdr {
    font-size: 0.65rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 1px; color: #64748B; margin-bottom: 0.1rem;
}
.platform-card {
    background: rgba(30,41,59,0.8);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(148,163,184,0.1);
    border-radius: 12px;
    padding: 1.2rem 1.4rem;
    transition: all 0.25s ease;
}
.platform-card:hover {
    border-color: rgba(148,163,184,0.2);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
}
.platform-stat-row {
    display: flex; justify-content: space-between;
    align-items: center;
    padding: 0.4rem 0;
    border-bottom: 1px solid rgba(148,163,184,0.07);
    font-size: 0.82rem;
}
.platform-stat-row:last-child { border-bottom: none; }
.platform-stat-val { font-weight: 700; color: #F1F5F9; }
.insight-bar {
    padding: 0.7rem 1rem;
    border-radius: 0 8px 8px 0;
    font-size: 0.82rem; color: #94A3B8; line-height: 1.5;
    margin: 0.75rem 0;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

# ── Data Loading ───────────────────────────────────────────────────────────────
@st.cache_data(ttl=300)
def load_summary_data():
    return IdentityResolver().get_identity_summary()

@st.cache_data(ttl=300)
def load_risk_data():
    import sqlite3
    engine = RiskEngine()
    df = engine.calculate_risk_scores()
    conn = sqlite3.connect('database/identitylens.db')
    identities = pd.read_sql_query("SELECT identity_id, department FROM identities", conn)
    conn.close()
    return df.merge(identities, on='identity_id', how='left')

@st.cache_data(ttl=300)
def load_platform_stats():
    import sqlite3
    conn = sqlite3.connect('database/identitylens.db')
    try:
        aws  = pd.read_sql_query("SELECT status FROM aws_accounts",  conn)
        ad   = pd.read_sql_query("SELECT status FROM ad_accounts",   conn)
        okta = pd.read_sql_query("SELECT status FROM okta_accounts", conn)
        tokens = pd.read_sql_query("SELECT COUNT(*) as c FROM api_tokens", conn).iloc[0]['c']
    except Exception:
        aws = ad = okta = pd.DataFrame()
        tokens = 0
    conn.close()
    return aws, ad, okta, tokens

summary = load_summary_data()
risk_df = load_risk_data()
aws_df, ad_df, okta_df, active_tokens = load_platform_stats()

critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
high_count     = len(risk_df[risk_df['risk_level'] == 'High'])
total_ids      = summary['total_identities']
correlated     = summary['has_all_three_platforms']
avg_risk       = round(risk_df['risk_score'].mean(), 1)

try:
    quarantined_count = 0
    import sqlite3
    conn = sqlite3.connect('database/identitylens.db')
    q = conn.execute("SELECT COUNT(*) FROM quarantine_records WHERE status='quarantined'").fetchone()
    if q: quarantined_count = q[0]
    conn.close()
except Exception:
    quarantined_count = 0

# ── Page Header ────────────────────────────────────────────────────────────────
now = datetime.now().strftime("%d %b %Y · %H:%M")
st.markdown(f"""
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid rgba(148,163,184,0.1);margin-bottom:1.5rem;">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#3B82F6;margin-bottom:0.3rem;">Executive Dashboard</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Security Operations Overview</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Real-time identity security posture · Last refreshed <strong style="color:#94A3B8;">{now}</strong>
        </p>
    </div>
    <div style="display:flex;align-items:center;gap:0.5rem;
                padding:0.3rem 0.9rem;
                background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#22C55E;
                letter-spacing:1px;text-transform:uppercase;">
        <span style="width:6px;height:6px;border-radius:50%;background:#22C55E;
                     display:inline-block;animation:pulse-dot 2s infinite;"></span>LIVE
    </div>
</div>
""", unsafe_allow_html=True)

# ── 6 Animated KPI Cards ───────────────────────────────────────────────────────
aws_count  = len(aws_df)  if not aws_df.empty  else 0
ad_count   = len(ad_df)   if not ad_df.empty   else 0
okta_count = len(okta_df) if not okta_df.empty else 0

from backend.anomaly_detection import AnomalyDetectionEngine
@st.cache_data(ttl=300)
def get_anomaly_count():
    try:
        return len(AnomalyDetectionEngine().detect_anomalies())
    except:
        return 0

anomaly_count = get_anomaly_count()

# ITDR-specific counts
@st.cache_data(ttl=300)
def get_itdr_counts():
    try:
        anoms = AnomalyDetectionEngine().detect_anomalies()
        sa_compromise = len(anoms[anoms['anomaly_type'] == 'SERVICE_ACCOUNT_COMPROMISE'])
        unauth_esc = len(anoms[anoms['anomaly_type'] == 'UNAUTHORIZED_PRIVILEGE_ESCALATION'])
        return sa_compromise, unauth_esc
    except:
        return 0, 0

sa_compromise_count, unauth_esc_count = get_itdr_counts()

st.markdown(f"""
<div class="kpi-grid" style="grid-template-columns: repeat(4, 1fr);">
    <div class="exec-kpi accent">
        <div class="stripe" style="background:#3B82F6;box-shadow:0 0 10px rgba(59,130,246,0.4);"></div>
        <div class="glow" style="background:#3B82F6;"></div>
        <div class="kpi-icon-bg">🆔</div>
        <div class="kpi-lbl">Total Identities</div>
        <div class="kpi-val" style="color:#3B82F6;">{total_ids}</div>
        <div class="kpi-sub">Across all enterprise platforms</div>
    </div>
    <div class="exec-kpi critical">
        <div class="stripe" style="background:#EF4444;box-shadow:0 0 10px rgba(239,68,68,0.4);"></div>
        <div class="glow" style="background:#EF4444;"></div>
        <div class="kpi-icon-bg">🚨</div>
        <div class="kpi-lbl">Critical Risks</div>
        <div class="kpi-val" style="color:#EF4444;">{critical_count}</div>
        <div class="kpi-sub">Require immediate action</div>
    </div>
    <div class="exec-kpi high">
        <div class="stripe" style="background:#F97316;box-shadow:0 0 10px rgba(249,115,22,0.4);"></div>
        <div class="glow" style="background:#F97316;"></div>
        <div class="kpi-icon-bg">⚠️</div>
        <div class="kpi-lbl">High Risks</div>
        <div class="kpi-val" style="color:#F97316;">{high_count}</div>
        <div class="kpi-sub">Review within 24 hours</div>
    </div>
    <div class="exec-kpi" style="">
        <div class="stripe" style="background:#8B5CF6;box-shadow:0 0 10px rgba(139,92,246,0.4);"></div>
        <div class="glow" style="background:#8B5CF6;"></div>
        <div class="kpi-icon-bg">🔒</div>
        <div class="kpi-lbl">Quarantined</div>
        <div class="kpi-val" style="color:#8B5CF6;">{quarantined_count}</div>
        <div class="kpi-sub">Access revoked accounts</div>
    </div>
</div>
<div class="kpi-grid" style="grid-template-columns: repeat(4, 1fr);">
    <div class="exec-kpi" style="">
        <div class="stripe" style="background:#F59E0B;box-shadow:0 0 10px rgba(245,158,11,0.4);"></div>
        <div class="glow" style="background:#F59E0B;"></div>
        <div class="kpi-icon-bg">☁️</div>
        <div class="kpi-lbl">AWS IAM Users</div>
        <div class="kpi-val" style="color:#F59E0B;">{aws_count}</div>
        <div class="kpi-sub">Active cloud identities</div>
    </div>
    <div class="exec-kpi" style="">
        <div class="stripe" style="background:#06B6D4;box-shadow:0 0 10px rgba(6,182,212,0.4);"></div>
        <div class="glow" style="background:#06B6D4;"></div>
        <div class="kpi-icon-bg">🔍</div>
        <div class="kpi-lbl">Anomalies Detected</div>
        <div class="kpi-val" style="color:#06B6D4;">{anomaly_count}</div>
        <div class="kpi-sub">Behavioural deviations</div>
    </div>
    <div class="exec-kpi" style="">
        <div class="stripe" style="background:#DC2626;box-shadow:0 0 10px rgba(220,38,38,0.4);"></div>
        <div class="glow" style="background:#DC2626;"></div>
        <div class="kpi-icon-bg">🤖</div>
        <div class="kpi-lbl">SA Compromise Alerts</div>
        <div class="kpi-val" style="color:#DC2626;">{sa_compromise_count}</div>
        <div class="kpi-sub">Composite ITDR indicators</div>
    </div>
    <div class="exec-kpi" style="">
        <div class="stripe" style="background:#EA580C;box-shadow:0 0 10px rgba(234,88,12,0.4);"></div>
        <div class="glow" style="background:#EA580C;"></div>
        <div class="kpi-icon-bg">⚡</div>
        <div class="kpi-lbl">Unauthorized Escalations</div>
        <div class="kpi-val" style="color:#EA580C;">{unauth_esc_count}</div>
        <div class="kpi-sub">No approved change ticket</div>
    </div>
</div>
""", unsafe_allow_html=True)

# Insight banner
if critical_count > 0:
    st.markdown(f"""
    <div class="insight-bar" style="background:rgba(239,68,68,0.06);border-left:3px solid #EF4444;">
        🚨 <strong style="color:#EF4444;">{critical_count} critical identities</strong> detected —
        these accounts pose immediate risk and should be investigated or quarantined before end of day.
    </div>""", unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="insight-bar" style="background:rgba(34,197,94,0.06);border-left:3px solid #22C55E;">
        ✅ No critical-risk identities found. Your organisation's posture looks healthy — keep monitoring for emerging threats.
    </div>""", unsafe_allow_html=True)

# ── Charts Row 1: Distribution + Risk Level ────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Identity & Risk Breakdown</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Identity Type Distribution</div>', unsafe_allow_html=True)
    type_df = pd.DataFrame(list(summary['types'].items()), columns=['Type', 'Count'])
    type_df = type_df.sort_values('Count', ascending=False)
    PALETTE = ['#3B82F6', '#8B5CF6', '#22C55E', '#F97316', '#EAB308', '#06B6D4']
    fig_types = px.pie(type_df, values='Count', names='Type', hole=0.58,
                       color_discrete_sequence=PALETTE)
    fig_types.update_layout(**DARK_LAYOUT,
        legend=dict(font=dict(color=TEXT_COLOR, size=11), bgcolor='rgba(0,0,0,0)',
                    orientation='v', yanchor='middle', y=0.5, xanchor='left', x=1.02),
        margin=dict(t=10, b=10, l=10, r=80), height=280,
        annotations=[dict(text=f"<b style='color:#F1F5F9'>{total_ids}</b><br><span style='font-size:9px;color:#64748B'>Total</span>",
                          x=0.5, y=0.5, font_size=18, showarrow=False, font_color='#F1F5F9')])
    fig_types.update_traces(textinfo='percent', textfont=dict(size=11, color='white'),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>',
        marker=dict(line=dict(color=DARK_BG, width=2)))
    st.plotly_chart(fig_types, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Risk Level Distribution</div>', unsafe_allow_html=True)
    risk_counts = risk_df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    order = ['Critical', 'High', 'Medium', 'Low']
    risk_counts['Risk Level'] = pd.Categorical(risk_counts['Risk Level'], categories=order, ordered=True)
    risk_counts = risk_counts.sort_values('Risk Level')
    fig_risk = px.bar(risk_counts, x='Risk Level', y='Count', color='Risk Level',
                      color_discrete_map=COLOR_MAP, text='Count')
    fig_risk.update_layout(**DARK_LAYOUT, showlegend=False,
        xaxis=dict(gridcolor=GRID_COLOR, title='', tickfont=dict(size=12, color=TEXT_COLOR)),
        yaxis=dict(gridcolor=GRID_COLOR, title='Count', tickfont=dict(size=11, color=TEXT_COLOR)),
        margin=dict(t=10, b=20, l=10, r=10), height=280, bargap=0.35)
    fig_risk.update_traces(textposition='outside',
        textfont=dict(color='#F1F5F9', size=13, weight=700),
        marker_line_color='rgba(0,0,0,0)', marker_opacity=0.9,
        hovertemplate='<b>%{x}</b><br>%{y} identities<extra></extra>')
    st.plotly_chart(fig_risk, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Risk Heatmap ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Risk Heatmap — Department × Severity</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Identity risk distribution across departments and severity levels</div>', unsafe_allow_html=True)

if 'department' in risk_df.columns and risk_df['department'].notna().any():
    heatmap_df = risk_df.dropna(subset=['department'])
    pivot = heatmap_df.groupby(['department', 'risk_level']).size().unstack(fill_value=0)
    for col in ['Critical', 'High', 'Medium', 'Low']:
        if col not in pivot.columns:
            pivot[col] = 0
    pivot = pivot[['Critical', 'High', 'Medium', 'Low']]
    z_vals = pivot.values

    fig_heat = go.Figure(data=go.Heatmap(
        z=z_vals,
        x=['Critical', 'High', 'Medium', 'Low'],
        y=pivot.index.tolist(),
        colorscale=[[0, '#1E293B'], [0.25, '#7C3AED'], [0.5, '#2563EB'], [0.75, '#D97706'], [1.0, '#EF4444']],
        text=z_vals,
        texttemplate='%{text}',
        textfont=dict(size=12, color='white'),
        hovertemplate='<b>%{y}</b> — %{x}<br>Count: %{z}<extra></extra>',
        showscale=True,
        colorbar=dict(
            bgcolor='rgba(0,0,0,0)', tickfont=dict(color=TEXT_COLOR, size=10),
            title=dict(text='Count', font=dict(color=TEXT_COLOR, size=10)),
            thickness=12, len=0.8,
        ),
    ))
    fig_heat.update_layout(**DARK_LAYOUT,
        margin=dict(t=10, b=10, l=10, r=60), height=320,
        xaxis=dict(tickfont=dict(size=12, color=TEXT_COLOR), side='top'),
        yaxis=dict(tickfont=dict(size=11, color=TEXT_COLOR)))
    st.plotly_chart(fig_heat, use_container_width=True)
else:
    st.info("Department data not available for heatmap.")
st.markdown('</div>', unsafe_allow_html=True)

# ── Risk Trends + Platform Comparison ─────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Trends & Platform Comparison</h2></div>', unsafe_allow_html=True)
col_t1, col_t2 = st.columns(2)

with col_t1:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Risk Score Trend (Simulated 4-Week Window)</div>', unsafe_allow_html=True)
    # Simulated trend based on current avg
    np.random.seed(42)
    dates = [datetime.now() - timedelta(days=27-i) for i in range(28)]
    base = avg_risk
    critical_trend = np.clip(np.cumsum(np.random.randn(28)*0.4) + critical_count, 0, None)
    high_trend     = np.clip(np.cumsum(np.random.randn(28)*0.6) + high_count, 0, None)
    avg_trend      = np.clip(np.cumsum(np.random.randn(28)*0.5) + base, 0, 100)

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Scatter(
        x=dates, y=avg_trend, name='Avg Risk Score',
        line=dict(color='#3B82F6', width=2),
        fill='tozeroy', fillcolor='rgba(59,130,246,0.08)',
        hovertemplate='%{x|%d %b}<br>Avg Score: %{y:.1f}<extra></extra>'
    ))
    fig_trend.add_trace(go.Scatter(
        x=dates, y=critical_trend, name='Critical Count',
        line=dict(color='#EF4444', width=2, dash='dot'),
        hovertemplate='%{x|%d %b}<br>Critical: %{y:.0f}<extra></extra>'
    ))
    fig_trend.add_trace(go.Scatter(
        x=dates, y=high_trend, name='High Count',
        line=dict(color='#F97316', width=2, dash='dash'),
        hovertemplate='%{x|%d %b}<br>High: %{y:.0f}<extra></extra>'
    ))
    fig_trend.update_layout(**DARK_LAYOUT,
        legend=dict(font=dict(color=TEXT_COLOR, size=10), bgcolor='rgba(0,0,0,0)',
                    orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        xaxis=dict(gridcolor=GRID_COLOR, tickfont=dict(size=10, color=TEXT_COLOR),
                   tickformat='%d %b'),
        yaxis=dict(gridcolor=GRID_COLOR, tickfont=dict(size=10, color=TEXT_COLOR)),
        margin=dict(t=30, b=20, l=10, r=10), height=280)
    st.plotly_chart(fig_trend, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_t2:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Platform Identity Comparison</div>', unsafe_allow_html=True)
    platforms = ['Active Directory', 'AWS IAM', 'Okta']
    counts    = [ad_count, aws_count, okta_count]
    PLAT_COLORS = ['#3B82F6', '#F59E0B', '#8B5CF6']

    fig_plat = go.Figure()
    fig_plat.add_trace(go.Bar(
        x=platforms, y=counts,
        marker_color=PLAT_COLORS,
        marker_opacity=0.85,
        text=counts, textposition='outside',
        textfont=dict(color='#F1F5F9', size=14, weight=700),
        marker_line_color='rgba(0,0,0,0)',
        hovertemplate='<b>%{x}</b><br>%{y} identities<extra></extra>',
        width=[0.45, 0.45, 0.45],
    ))
    for plat, clr, cnt in zip(platforms, PLAT_COLORS, counts):
        fig_plat.add_annotation(
            x=plat, y=-8, text=f"<span style='color:{clr}'>{plat}</span>",
            showarrow=False, font=dict(size=10, color=clr)
        )
    fig_plat.update_layout(**DARK_LAYOUT, showlegend=False,
        xaxis=dict(gridcolor=GRID_COLOR, tickfont=dict(size=11, color=TEXT_COLOR), showticklabels=True),
        yaxis=dict(gridcolor=GRID_COLOR, tickfont=dict(size=11, color=TEXT_COLOR),
                   title='Identity Count', range=[0, max(counts)*1.25 if counts else 10]),
        margin=dict(t=20, b=20, l=10, r=10), height=280, bargap=0.35)
    st.plotly_chart(fig_plat, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Overall Risk Gauge ─────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Overall Risk Posture</h2></div>', unsafe_allow_html=True)
col_g1, col_g2, col_g3 = st.columns([1, 2, 1])

with col_g2:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    risk_label = "Critical" if avg_risk > 75 else "High" if avg_risk > 50 else "Medium" if avg_risk > 25 else "Low"
    gauge_color = '#EF4444' if avg_risk > 75 else '#F97316' if avg_risk > 50 else '#EAB308' if avg_risk > 25 else '#22C55E'
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=avg_risk,
        number=dict(suffix="/100", font=dict(size=28, color=gauge_color, family=FONT_FAM)),
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#475569', 'tickwidth': 1,
                     'tickvals': [0, 25, 50, 75, 100],
                     'ticktext': ['0', '25', '50', '75', '100'],
                     'tickfont': dict(size=10, color=TEXT_COLOR)},
            'bar': {'color': gauge_color, 'thickness': 0.22},
            'bgcolor': CARD_BG,
            'borderwidth': 0,
            'steps': [
                {'range': [0,   25],  'color': 'rgba(34,197,94,0.08)'},
                {'range': [25,  50],  'color': 'rgba(234,179,8,0.08)'},
                {'range': [50,  75],  'color': 'rgba(249,115,22,0.08)'},
                {'range': [75, 100],  'color': 'rgba(239,68,68,0.08)'},
            ],
            'threshold': {'line': {'color': gauge_color, 'width': 3}, 'thickness': 0.85, 'value': avg_risk}
        },
        title=dict(
            text=f"Average Organisation Risk Score<br><span style='font-size:12px;color:{TEXT_COLOR}'>Current level: <b style='color:{gauge_color}'>{risk_label}</b></span>",
            font=dict(size=14, color='#F1F5F9', family=FONT_FAM)
        )
    ))
    fig_gauge.update_layout(paper_bgcolor=DARK_BG, font=dict(family=FONT_FAM),
        height=340, margin=dict(t=120, b=20, l=40, r=40))
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Platform Overview Cards ────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Platform Overview</h2></div>', unsafe_allow_html=True)
col_p1, col_p2, col_p3 = st.columns(3)

def dormant_count(df, status_col='status'):
    if df.empty or status_col not in df.columns:
        return 0
    return len(df[df[status_col].str.lower().isin(['inactive', 'disabled', 'suspended'])])

def admin_count(df, role_col=None, policy_col=None):
    if df.empty:
        return 0
    if role_col and role_col in df.columns:
        return df[role_col].str.lower().str.contains('admin', na=False).sum()
    if policy_col and policy_col in df.columns:
        return df[policy_col].str.lower().str.contains('admin|root|full', na=False).sum()
    return 0

try:
    import sqlite3
    conn = sqlite3.connect('database/identitylens.db')
    ad_full   = pd.read_sql_query("SELECT status, role   FROM ad_accounts",   conn)
    aws_full  = pd.read_sql_query("SELECT status, policy FROM aws_accounts",  conn)
    okta_full = pd.read_sql_query("SELECT status, role   FROM okta_accounts", conn)
    tok_count = pd.read_sql_query("SELECT COUNT(*) as c FROM api_tokens", conn).iloc[0]['c']
    conn.close()
except Exception as e:
    ad_full = aws_full = okta_full = pd.DataFrame()
    tok_count = active_tokens

with col_p1:
    ad_dormant = dormant_count(ad_full)
    ad_admin   = admin_count(ad_full, role_col='role')
    st.markdown(f"""
    <div class="platform-card">
        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:1rem;">
            <div style="width:28px;height:28px;background:rgba(59,130,246,0.15);border:1px solid rgba(59,130,246,0.3);
                        border-radius:8px;display:grid;place-items:center;font-size:0.9rem;">🏢</div>
            <div>
                <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Platform</div>
                <div style="font-size:0.9rem;font-weight:700;color:#3B82F6;">Active Directory</div>
            </div>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Total Users</span>
            <span class="platform-stat-val">{len(ad_full)}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Admin Accounts</span>
            <span class="platform-stat-val" style="color:#F97316;">{ad_admin}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Dormant Accounts</span>
            <span class="platform-stat-val" style="color:#EAB308;">{ad_dormant}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Status</span>
            <span style="background:rgba(34,197,94,0.1);color:#22C55E;padding:2px 8px;border-radius:100px;font-size:0.65rem;font-weight:700;">CONNECTED</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_p2:
    aws_dormant = dormant_count(aws_full)
    aws_admin   = admin_count(aws_full, policy_col='policy')
    st.markdown(f"""
    <div class="platform-card">
        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:1rem;">
            <div style="width:28px;height:28px;background:rgba(245,158,11,0.15);border:1px solid rgba(245,158,11,0.3);
                        border-radius:8px;display:grid;place-items:center;font-size:0.9rem;">☁️</div>
            <div>
                <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Platform</div>
                <div style="font-size:0.9rem;font-weight:700;color:#F59E0B;">AWS IAM</div>
            </div>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Total Users</span>
            <span class="platform-stat-val">{len(aws_full)}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Admin / Root</span>
            <span class="platform-stat-val" style="color:#F97316;">{aws_admin}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Dormant Accounts</span>
            <span class="platform-stat-val" style="color:#EAB308;">{aws_dormant}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Active Tokens</span>
            <span class="platform-stat-val" style="color:#06B6D4;">{tok_count}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_p3:
    okta_dormant = dormant_count(okta_full)
    okta_admin   = admin_count(okta_full, role_col='role')
    st.markdown(f"""
    <div class="platform-card">
        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:1rem;">
            <div style="width:28px;height:28px;background:rgba(139,92,246,0.15);border:1px solid rgba(139,92,246,0.3);
                        border-radius:8px;display:grid;place-items:center;font-size:0.9rem;">🔐</div>
            <div>
                <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Platform</div>
                <div style="font-size:0.9rem;font-weight:700;color:#8B5CF6;">Okta</div>
            </div>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Total Users</span>
            <span class="platform-stat-val">{len(okta_full)}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Admin Roles</span>
            <span class="platform-stat-val" style="color:#F97316;">{okta_admin}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Dormant Accounts</span>
            <span class="platform-stat-val" style="color:#EAB308;">{okta_dormant}</span>
        </div>
        <div class="platform-stat-row">
            <span style="color:#94A3B8;font-size:0.8rem;">Active Tokens</span>
            <span class="platform-stat-val" style="color:#06B6D4;">{tok_count}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ── Department Breakdown ───────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Risk × Department Breakdown</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Sunburst — hover to explore departments and risk levels</div>', unsafe_allow_html=True)

if 'department' in risk_df.columns and risk_df['department'].notna().any():
    dept_risk_df = risk_df.dropna(subset=['department'])
    fig_sun = px.sunburst(dept_risk_df, path=['risk_level', 'department'],
        color='risk_level', color_discrete_map=COLOR_MAP)
    fig_sun.update_layout(paper_bgcolor=DARK_BG, font=dict(family=FONT_FAM, color=TEXT_COLOR),
        height=400, margin=dict(t=10, b=10, l=10, r=10))
    fig_sun.update_traces(
        hovertemplate='<b>%{label}</b><br>Count: %{value}<extra></extra>',
        insidetextorientation='radial',
        textfont=dict(color='white', size=11)
    )
    st.plotly_chart(fig_sun, use_container_width=True)
else:
    # Fallback bar chart
    fallback_df = risk_df.groupby('risk_level').size().reset_index(name='count')
    fig_fb = px.bar(fallback_df, x='risk_level', y='count', color='risk_level',
                    color_discrete_map=COLOR_MAP, text='count')
    fig_fb.update_layout(**DARK_LAYOUT, showlegend=False, height=350,
        margin=dict(t=10, b=20, l=10, r=10))
    st.plotly_chart(fig_fb, use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)
