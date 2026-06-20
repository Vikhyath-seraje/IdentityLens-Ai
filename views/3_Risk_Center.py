import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver

# ── Page header ────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Risk Management</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Risk Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Comprehensive identity risk scoring with prioritised remediation intelligence.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(230,0,40,0.06);border:1px solid rgba(230,0,40,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#E60028;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">RISK ANALYSIS</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(12px)}
    to{opacity:1;transform:translateY(0)}
}
.chart-wrapper {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1rem 0.5rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    transition:box-shadow 0.25s;animation:fadeSlideUp 0.4s ease both;
}
.chart-wrapper:hover { box-shadow:0 6px 20px rgba(0,0,0,0.1); }
.section-title h2 {
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}
.kpi-insight { font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4; }
.risk-insight-bar {
    display:flex;align-items:center;gap:0.8rem;
    padding:0.65rem 1rem;margin:0.8rem 0;border-radius:8px;font-size:0.83rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_risk_data():
    engine = RiskEngine()
    risk_df = engine.calculate_risk_scores()
    resolver = IdentityResolver()
    identities_df = resolver.get_resolved_identities()
    return risk_df.merge(identities_df[['identity_id', 'name', 'department', 'type']], on='identity_id', how='left')

risk_df = load_risk_data()

critical = len(risk_df[risk_df['risk_level'] == 'Critical'])
high     = len(risk_df[risk_df['risk_level'] == 'High'])
medium   = len(risk_df[risk_df['risk_level'] == 'Medium'])
low      = len(risk_df[risk_df['risk_level'] == 'Low'])
avg_risk = round(risk_df['risk_score'].mean(), 1)

# ── KPI Row ─────────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Critical", critical, delta=f"{critical} immediate" if critical else "None — clean", delta_color="inverse")
    st.markdown('<div class="kpi-insight">Needs immediate action</div>', unsafe_allow_html=True)
with col2:
    st.metric("High", high, delta=f"{high} to address" if high else "None — great", delta_color="inverse")
    st.markdown('<div class="kpi-insight">Review within 24 hrs</div>', unsafe_allow_html=True)
with col3:
    st.metric("Medium", medium)
    st.markdown('<div class="kpi-insight">Monitor regularly</div>', unsafe_allow_html=True)
with col4:
    st.metric("Low", low)
    st.markdown('<div class="kpi-insight">Healthy identities</div>', unsafe_allow_html=True)
with col5:
    st.metric("Avg Score", f"{avg_risk}/100")
    posture = "Elevated" if avg_risk > 55 else "Moderate" if avg_risk > 35 else "Healthy"
    st.markdown(f'<div class="kpi-insight">Posture: <strong>{posture}</strong></div>', unsafe_allow_html=True)

# Contextual risk insight
if critical > 0:
    st.markdown(f"""
    <div class="risk-insight-bar" style="background:rgba(220,38,38,0.05);border:1px solid rgba(220,38,38,0.2);">
        <span style="font-size:1.2rem;"></span>
        <span><strong style="color:#DC2626">{critical} critical identities</strong> detected. Use the table below to identify and prioritise remediation — these accounts may have been compromised or carry excessive privileges.</span>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="risk-insight-bar" style="background:rgba(22,163,74,0.05);border:1px solid rgba(22,163,74,0.2);">
        <span style="font-size:1.2rem;"></span>
        <span>No critical-risk identities at this time. Continue to monitor high-risk accounts and keep privilege counts minimal.</span>
    </div>
    """, unsafe_allow_html=True)

st.divider()

# ── Filters & Table ─────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Risk Register</h2></div>', unsafe_allow_html=True)

col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
with col_f1:
    selected_level = st.selectbox("Risk Level", ['All', 'Critical', 'High', 'Medium', 'Low'])
with col_f2:
    departments = ['All'] + sorted(risk_df['department'].dropna().unique().tolist())
    selected_dept = st.selectbox("Department", departments)
with col_f3:
    search_name = st.text_input(" Search by name or ID", placeholder="Type a name, ID or department…")

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

total_shown = len(filtered_df)
st.caption(f"Showing **{total_shown}** of **{len(risk_df)}** identities · sorted by highest risk first")

st.dataframe(
    filtered_df[['identity_id', 'name', 'department', 'type', 'risk_score', 'risk_level', 'anomaly_count', 'privilege_count']]
        .sort_values(by='risk_score', ascending=False),
    use_container_width=True,
    height=340,
    column_config={
        'identity_id':    st.column_config.TextColumn('Identity ID',   width='small'),
        'name':           st.column_config.TextColumn('Name',          width='medium'),
        'department':     st.column_config.TextColumn('Department',    width='medium'),
        'type':           st.column_config.TextColumn('Type',          width='small'),
        'risk_score':     st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=100, format='%d %%'),
        'risk_level':     st.column_config.TextColumn('Level',         width='small'),
        'anomaly_count':  st.column_config.NumberColumn('Anomalies',   width='small'),
        'privilege_count':st.column_config.NumberColumn('Privileges',  width='small'),
    }
)

st.divider()

# ── Charts Row ──────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Risk Analytics</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    color_map = {'Critical': '#DC2626', 'High': '#EA580C', 'Medium': '#D97706', 'Low': '#16A34A'}
    fig_hist = px.histogram(
        risk_df, x="risk_score", color="risk_level", nbins=25,
        color_discrete_map=color_map, opacity=0.85,
        title="How risk scores are distributed across all identities",
        labels={'risk_score': 'Risk Score', 'count': 'Identities'}
    )
    fig_hist.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=13, color='#4A4A4A'),
        legend=dict(font=dict(color='#4A4A4A', size=11), bgcolor='rgba(0,0,0,0)',
                    orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Risk Score', tickfont=dict(size=11)),
        yaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Number of Identities', tickfont=dict(size=11)),
        margin=dict(t=55, b=20, l=10, r=10),
        bargap=0.03,
        height=300,
    )
    fig_hist.update_traces(
        hovertemplate='Risk Score: <b>%{x}</b><br>Count: <b>%{y}</b><extra></extra>',
        marker_line_color='rgba(255,255,255,0.5)', marker_line_width=0.5,
    )
    st.plotly_chart(fig_hist, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    dept_risk = risk_df.groupby('department')['risk_score'].mean().reset_index()
    dept_risk = dept_risk.sort_values('risk_score', ascending=True)
    dept_risk['color_cat'] = dept_risk['risk_score'].apply(
        lambda s: 'Critical' if s >= 80 else 'High' if s >= 60 else 'Medium' if s >= 30 else 'Low'
    )
    fig_dept = px.bar(
        dept_risk, x='risk_score', y='department', orientation='h',
        color='color_cat',
        color_discrete_map=color_map,
        text=dept_risk['risk_score'].round(1),
        title="Average risk score per department — who needs attention?",
        labels={'risk_score': 'Avg Risk Score', 'department': ''}
    )
    fig_dept.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=13, color='#4A4A4A'),
        showlegend=False,
        xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Avg Risk Score', range=[0, 105], tickfont=dict(size=11)),
        yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#4A4A4A')),
        margin=dict(t=55, b=20, l=10, r=40),
        height=300,
        bargap=0.3,
    )
    fig_dept.update_traces(
        textposition='outside',
        textfont=dict(color='#1A1A1A', size=12, weight=600),
        hovertemplate='<b>%{y}</b><br>Avg Risk: <b>%{x:.1f}</b><extra></extra>',
        marker_line_color='rgba(0,0,0,0)',
    )
    st.plotly_chart(fig_dept, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Top 10 Highest Risk ─────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Top 10 Highest-Risk Identities</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

top10 = risk_df.nlargest(10, 'risk_score').copy()
top10['display_name'] = top10['name'].fillna(top10['identity_id'])
top10['risk_cat'] = top10['risk_score'].apply(
    lambda s: 'Critical' if s >= 80 else 'High' if s >= 60 else 'Medium' if s >= 30 else 'Low'
)

fig_top = go.Figure()

for level, clr in [('Critical', '#DC2626'), ('High', '#EA580C'), ('Medium', '#D97706'), ('Low', '#16A34A')]:
    subset = top10[top10['risk_cat'] == level]
    if not subset.empty:
        fig_top.add_trace(go.Bar(
            x=subset['risk_score'],
            y=subset['display_name'],
            orientation='h',
            name=level,
            marker_color=clr,
            marker_opacity=0.85,
            text=subset['risk_score'].round(1),
            textposition='outside',
            textfont=dict(color='#1A1A1A', size=12, weight=700),
            hovertemplate='<b>%{y}</b><br>Risk Score: <b>%{x:.1f}</b><extra></extra>',
            marker_line_color='rgba(0,0,0,0)',
        ))

fig_top.update_layout(
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
    font=dict(family='Inter, sans-serif', color='#1A1A1A'),
    barmode='stack',
    showlegend=True,
    legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1,
                font=dict(size=11, color='#4A4A4A'), bgcolor='rgba(0,0,0,0)'),
    height=380,
    xaxis=dict(gridcolor='rgba(0,0,0,0.06)', range=[0, 115], title='Risk Score', tickfont=dict(size=11)),
    yaxis=dict(gridcolor='rgba(0,0,0,0)', autorange='reversed', tickfont=dict(size=11, color='#1A1A1A')),
    margin=dict(t=30, b=20, l=10, r=50),
)

# Add a reference line at score 80 (critical threshold)
fig_top.add_vline(x=80, line_dash="dot", line_color="rgba(220,38,38,0.4)", line_width=1.5,
                  annotation_text="Critical threshold", annotation_position="top right",
                  annotation_font=dict(size=10, color='#DC2626'))

st.plotly_chart(fig_top, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

# ── Risk by Type ────────────────────────────────────────────────────────────────
if 'type' in risk_df.columns:
    st.markdown('<div class="section-title"><h2>Risk Profile by Identity Type</h2></div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

    type_risk = risk_df.groupby(['type', 'risk_level']).size().reset_index(name='count')
    fig_type = px.bar(
        type_risk, x='type', y='count', color='risk_level',
        color_discrete_map=color_map,
        title="Which identity types carry the most risk?",
        labels={'type': 'Identity Type', 'count': 'Count', 'risk_level': 'Risk Level'},
        barmode='stack',
    )
    fig_type.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=13, color='#4A4A4A'),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1,
                    font=dict(size=11, color='#4A4A4A'), bgcolor='rgba(0,0,0,0)'),
        xaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=12)),
        yaxis=dict(gridcolor='rgba(0,0,0,0.06)', tickfont=dict(size=11)),
        bargap=0.35,
        height=280,
        margin=dict(t=55, b=20),
    )
    fig_type.update_traces(
        hovertemplate='<b>%{x}</b> — %{data.name}<br>Count: <b>%{y}</b><extra></extra>',
        marker_line_color='rgba(255,255,255,0.5)', marker_line_width=0.5,
    )
    st.plotly_chart(fig_type, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
