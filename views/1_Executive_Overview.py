import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver

# ── Page header ────────────────────────────────────────────────────────────────
now = datetime.now().strftime("%d %b %Y · %H:%M")
st.markdown(f"""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Dashboard</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Executive Overview</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Real-time identity security posture — last refreshed <strong>{now}</strong>
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;padding:0.25rem 0.75rem;
                background:rgba(0,122,76,0.06);border:1px solid rgba(0,122,76,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#007A4C;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">
        <span style="width:7px;height:7px;border-radius:50%;background:#007A4C;display:inline-block;
                     animation:pulse 2s infinite;"></span>LIVE
    </span>
</div>
</div>
<style>
@keyframes pulse {{
    0%,100%{{opacity:1;transform:scale(1)}}
    50%{{opacity:0.5;transform:scale(1.3)}}
}}
@keyframes fadeSlideUp {{
    from{{opacity:0;transform:translateY(12px)}}
    to{{opacity:1;transform:translateY(0)}}
}}
.kpi-insight {{
    font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4;
}}
.chart-wrapper {{
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1rem 0.5rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    transition:box-shadow 0.2s;animation:fadeSlideUp 0.4s ease both;
}}
.chart-wrapper:hover {{ box-shadow:0 4px 16px rgba(0,0,0,0.1); }}
.section-title h2 {{
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}}
.insight-banner {{
    background:linear-gradient(90deg,rgba(230,0,40,0.04),rgba(255,255,255,0));
    border-left:3px solid #E60028;border-radius:0 6px 6px 0;
    padding:0.65rem 1rem;margin:0.75rem 0;font-size:0.83rem;color:#4A4A4A;line-height:1.5;
}}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_summary_data():
    resolver = IdentityResolver()
    return resolver.get_identity_summary()

@st.cache_data(ttl=300)
def load_risk_data():
    import sqlite3
    engine = RiskEngine()
    df = engine.calculate_risk_scores()
    # Join department from identities table
    conn = sqlite3.connect('database/identitylens.db')
    identities = pd.read_sql_query("SELECT identity_id, department FROM identities", conn)
    conn.close()
    df = df.merge(identities, on='identity_id', how='left')
    return df

summary = load_summary_data()
risk_df = load_risk_data()

critical_count = len(risk_df[risk_df['risk_level'] == 'Critical'])
high_count     = len(risk_df[risk_df['risk_level'] == 'High'])
total_ids      = summary['total_identities']
correlated     = summary['has_all_three_platforms']
avg_risk       = round(risk_df['risk_score'].mean(), 1)

# ── KPI Row ────────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Identities", total_ids, help="All distinct identities across AD, AWS & Okta")
    st.markdown('<div class="kpi-insight">Across all enterprise platforms</div>', unsafe_allow_html=True)
with col2:
    st.metric("Fully Correlated", correlated, help="Identities present on AD, AWS and Okta simultaneously")
    pct = round(correlated / total_ids * 100) if total_ids else 0
    st.markdown(f'<div class="kpi-insight">{pct}% have all 3 platforms</div>', unsafe_allow_html=True)
with col3:
    st.metric("Critical Risk", critical_count, delta=f"{critical_count} need action", delta_color="inverse")
    st.markdown('<div class="kpi-insight">Require immediate attention</div>', unsafe_allow_html=True)
with col4:
    st.metric("High Risk", high_count, delta=f"{high_count} to review", delta_color="inverse")
    st.markdown('<div class="kpi-insight">Should be reviewed today</div>', unsafe_allow_html=True)
with col5:
    delta_color = "inverse" if avg_risk > 50 else "normal"
    st.metric("Avg Risk Score", f"{avg_risk}/100", delta=f"{'Elevated' if avg_risk > 50 else 'Healthy'}", delta_color=delta_color)
    st.markdown('<div class="kpi-insight">Organisation-wide posture</div>', unsafe_allow_html=True)

# Contextual insight banner
if critical_count > 0:
    st.markdown(f'<div class="insight-banner"><strong>{critical_count} critical identities</strong> detected — these accounts pose immediate risk and should be investigated or quarantined before end of day.</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="insight-banner">No critical-risk identities found. Your organisation\'s posture looks healthy — keep monitoring for emerging threats.</div>', unsafe_allow_html=True)

st.divider()

# ── Charts Row 1 ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity & Risk Breakdown</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    type_df = pd.DataFrame(list(summary['types'].items()), columns=['Type', 'Count'])
    type_df = type_df.sort_values('Count', ascending=False)

    PALETTE = ['#E60028', '#1a56db', '#10b981', '#f59e0b', '#8b5cf6', '#06b6d4']
    fig_types = px.pie(
        type_df, values='Count', names='Type', hole=0.58,
        color_discrete_sequence=PALETTE,
        title="Identity Type Distribution"
    )
    fig_types.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=14, color='#1A1A1A', family='Inter, sans-serif'),
        legend=dict(font=dict(color='#4A4A4A', size=12), bgcolor='rgba(0,0,0,0)',
                    orientation='v', yanchor='middle', y=0.5, xanchor='left', x=1.02),
        margin=dict(t=50, b=10, l=10, r=80),
        height=300,
        annotations=[dict(
            text=f"<b>{total_ids}</b><br><span style='font-size:10px'>Total</span>",
            x=0.5, y=0.5, font_size=18, showarrow=False, font_color='#1A1A1A'
        )]
    )
    fig_types.update_traces(
        textinfo='percent',
        textfont=dict(size=12, color='white'),
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Share: %{percent}<extra></extra>',
        pull=[0.04 if i == 0 else 0 for i in range(len(type_df))],
        marker=dict(line=dict(color='white', width=2))
    )
    st.plotly_chart(fig_types, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    risk_counts = risk_df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    order = ['Critical', 'High', 'Medium', 'Low']
    risk_counts['Risk Level'] = pd.Categorical(risk_counts['Risk Level'], categories=order, ordered=True)
    risk_counts = risk_counts.sort_values('Risk Level')

    color_map = {
        'Critical': '#DC2626',
        'High':     '#EA580C',
        'Medium':   '#D97706',
        'Low':      '#16A34A'
    }
    fig_risk = px.bar(
        risk_counts, x='Risk Level', y='Count', color='Risk Level',
        color_discrete_map=color_map, text='Count',
        title="Risk Level Distribution"
    )
    fig_risk.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=14, color='#1A1A1A', family='Inter, sans-serif'),
        showlegend=False,
        xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='', tickfont=dict(size=12, color='#4A4A4A')),
        yaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Number of Identities', tickfont=dict(size=11)),
        margin=dict(t=50, b=20, l=10, r=20),
        height=300,
        bargap=0.35,
    )
    fig_risk.update_traces(
        textposition='outside',
        textfont=dict(color='#1A1A1A', size=13, weight=700),
        marker_line_color='rgba(0,0,0,0)',
        hovertemplate='<b>%{x}</b><br>%{y} identities<extra></extra>',
        marker_opacity=0.9,
    )
    st.plotly_chart(fig_risk, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Department Bar ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identities by Department</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

dept_df = pd.DataFrame(list(summary['departments'].items()), columns=['Department', 'Count'])
dept_df = dept_df.sort_values('Count', ascending=True)
max_count = dept_df['Count'].max()

fig_dept = px.bar(
    dept_df, x='Count', y='Department', orientation='h',
    color='Count',
    color_continuous_scale=[[0, '#fde8e8'], [0.5, '#f87171'], [1.0, '#E60028']],
    text='Count',
    title="Headcount per Department"
)
fig_dept.update_layout(
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
    font=dict(family='Inter, sans-serif', color='#1A1A1A'),
    title_font=dict(size=14, color='#1A1A1A', family='Inter, sans-serif'),
    height=320,
    showlegend=False,
    coloraxis_showscale=False,
    xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Identity Count', range=[0, max_count * 1.15]),
    yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=12, color='#4A4A4A')),
    margin=dict(t=40, b=20, l=10, r=40),
)
fig_dept.update_traces(
    textposition='outside',
    textfont=dict(color='#1A1A1A', size=12, weight=600),
    marker_line_color='rgba(0,0,0,0)',
    hovertemplate='<b>%{y}</b><br>%{x} identities<extra></extra>',
)
st.plotly_chart(fig_dept, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ── Risk Gauge + Trend Row ─────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Overall Risk Posture</h2></div>', unsafe_allow_html=True)

col_g1, col_g2, col_g3 = st.columns([1, 2, 1])
with col_g2:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    risk_label = "Critical" if avg_risk > 75 else "High" if avg_risk > 50 else "Medium" if avg_risk > 25 else "Low"
    gauge_color = '#DC2626' if avg_risk > 75 else '#EA580C' if avg_risk > 50 else '#D97706' if avg_risk > 25 else '#16A34A'

    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=avg_risk,
        number=dict(suffix="/100", font=dict(size=28, color=gauge_color, family='Inter, sans-serif')),
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#9E9E9E', 'tickwidth': 1,
                     'tickvals': [0, 25, 50, 75, 100],
                     'ticktext': ['0', '25', '50', '75', '100'],
                     'tickfont': dict(size=11, color='#6B6B6B')},
            'bar': {'color': gauge_color, 'thickness': 0.25},
            'bgcolor': 'white',
            'borderwidth': 0,
            'steps': [
                {'range': [0, 25],  'color': 'rgba(22,163,74,0.12)'},
                {'range': [25, 50], 'color': 'rgba(217,119,6,0.12)'},
                {'range': [50, 75], 'color': 'rgba(234,88,12,0.12)'},
                {'range': [75, 100], 'color': 'rgba(220,38,38,0.12)'},
            ],
            'threshold': {
                'line': {'color': gauge_color, 'width': 3},
                'thickness': 0.8, 'value': avg_risk
            }
        },
        title=dict(
            text=f"Average Organisation Risk Score<br><span style='font-size:13px;color:#6B6B6B'>Current level: <b style='color:{gauge_color}'>{risk_label}</b></span>",
            font=dict(size=15, color='#1A1A1A', family='Inter, sans-serif')
        )
    ))
    fig_gauge.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif'),
        height=350,
        margin=dict(t=120, b=20, l=40, r=40),
    )
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Risk Breakdown Sunburst ────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Risk × Department Breakdown</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

if 'department' in risk_df.columns and risk_df['department'].notna().any():
    dept_risk_df = risk_df.dropna(subset=['department'])
    fig_sun = px.sunburst(
        dept_risk_df, path=['risk_level', 'department'],
        color='risk_level',
        color_discrete_map={
            'Critical': '#DC2626', 'High': '#EA580C',
            'Medium': '#D97706', 'Low': '#16A34A'
        },
        title="Risk Level by Department — hover to explore"
    )
    fig_sun.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=14, color='#1A1A1A'),
        height=420,
        margin=dict(t=50, b=10, l=10, r=10),
    )
    fig_sun.update_traces(
        hovertemplate='<b>%{label}</b><br>Count: %{value}<extra></extra>',
        insidetextorientation='radial'
    )
    st.plotly_chart(fig_sun, use_container_width=True)
else:
    # Fallback: stacked bar chart by risk level
    fallback_df = risk_df.groupby('risk_level').size().reset_index(name='count')
    color_map = {'Critical': '#DC2626', 'High': '#EA580C', 'Medium': '#D97706', 'Low': '#16A34A'}
    fig_fallback = px.bar(
        fallback_df, x='risk_level', y='count', color='risk_level',
        color_discrete_map=color_map, text='count',
        title="Risk Level Distribution"
    )
    fig_fallback.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        showlegend=False, height=400,
        margin=dict(t=50, b=20, l=10, r=10)
    )
    st.plotly_chart(fig_fallback, use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)
