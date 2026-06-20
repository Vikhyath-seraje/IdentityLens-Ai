import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver


def _clr_to_rgba(hex_color):
    """Convert hex color to RGB string for CSS rgba()."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"

DARK_BG  = '#0F172A'
CARD_BG  = '#1E293B'
TEXT_COL = '#94A3B8'
FONT_FAM = 'Inter, sans-serif'
GRID_COL = 'rgba(148,163,184,0.08)'
DARK_LAYOUT = dict(
    paper_bgcolor=DARK_BG, plot_bgcolor=CARD_BG,
    font=dict(family=FONT_FAM, color=TEXT_COL),
    title_font=dict(size=13, color='#F1F5F9', family=FONT_FAM),
)
COLOR_MAP = {
    'Critical': '#EF4444',
    'High':     '#F97316',
    'Medium':   '#EAB308',
    'Low':      '#22C55E',
}

st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
.risk-page-hdr {
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
.risk-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.3s ease;animation:fadeIn 0.4s ease both;
}
.risk-kpi:hover { border-color:rgba(148,163,184,0.22);transform:translateY(-2px); }
.risk-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.risk-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1; }
.risk-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.chart-wrapper {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1rem 0.5rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.chart-wrapper:hover { border-color:rgba(148,163,184,0.18);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.chart-hdr { font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem; }
.risk-insight-bar {
    display:flex;align-items:center;gap:0.8rem;
    padding:0.65rem 1rem;margin:0.8rem 0;border-radius:0 8px 8px 0;font-size:0.82rem;
}
.risk-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1.2rem;margin-bottom:0.6rem;
    transition:all 0.25s ease;animation:fadeIn 0.35s ease both;
}
.risk-card:hover { border-color:rgba(148,163,184,0.2);transform:translateX(3px); }
.risk-card.critical { border-left:3px solid #EF4444;box-shadow:2px 0 16px rgba(239,68,68,0.06) inset; }
.risk-card.high     { border-left:3px solid #F97316;box-shadow:2px 0 16px rgba(249,115,22,0.06) inset; }
.risk-card.medium   { border-left:3px solid #EAB308;box-shadow:2px 0 16px rgba(234,179,8,0.06) inset; }
.risk-card.low      { border-left:3px solid #22C55E;box-shadow:2px 0 16px rgba(34,197,94,0.06) inset; }
.risk-card-name { font-size:0.9rem;font-weight:700;color:#F1F5F9; }
.risk-card-meta { font-size:0.75rem;color:#64748B;margin-top:0.2rem; }
.risk-score-pill {
    display:inline-flex;align-items:center;padding:0.2rem 0.7rem;
    border-radius:100px;font-size:0.75rem;font-weight:800;
}
.action-btn {
    display:inline-flex;align-items:center;gap:0.3rem;
    padding:0.2rem 0.65rem;border-radius:6px;font-size:0.68rem;font-weight:600;
    border:1px solid rgba(148,163,184,0.2);color:#94A3B8;cursor:pointer;
    transition:all 0.15s;margin-right:0.3rem;background:rgba(30,41,59,0.5);
    text-decoration:none;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

st.markdown("""
<div class="risk-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#EF4444;margin-bottom:0.3rem;">Risk Management</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Risk Center</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Comprehensive identity risk scoring with prioritised remediation intelligence.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#EF4444;
                letter-spacing:1px;text-transform:uppercase;">⚡ RISK ANALYSIS</span>
</div>
""", unsafe_allow_html=True)

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

# ── KPI Row ────────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)
kpi_items = [
    (col1, "Critical",   critical, "#EF4444",  "Needs immediate action"),
    (col2, "High",       high,     "#F97316",  "Review within 24 hrs"),
    (col3, "Medium",     medium,   "#EAB308",  "Monitor regularly"),
    (col4, "Low",        low,      "#22C55E",  "Healthy identities"),
    (col5, "Avg Score",  f"{avg_risk}/100", "#3B82F6",
           "Elevated" if avg_risk > 55 else "Moderate" if avg_risk > 35 else "Healthy"),
]
for col, lbl, val, clr, sub in kpi_items:
    with col:
        st.markdown(f"""
        <div class="risk-kpi">
            <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                        background:{clr};box-shadow:0 0 10px {clr}44;"></div>
            <div class="risk-kpi-lbl">{lbl}</div>
            <div class="risk-kpi-val" style="color:{clr};">{val}</div>
            <div class="risk-kpi-sub">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

# Contextual banner
if critical > 0:
    st.markdown(f"""
    <div class="risk-insight-bar" style="background:rgba(239,68,68,0.06);border-left:3px solid #EF4444;">
        🚨 <strong style="color:#EF4444;">{critical} critical identities</strong> detected —
        investigate and prioritise remediation immediately.
    </div>""", unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="risk-insight-bar" style="background:rgba(34,197,94,0.06);border-left:3px solid #22C55E;">
        ✅ No critical-risk identities at this time. Continue monitoring high-risk accounts.
    </div>""", unsafe_allow_html=True)

st.divider()

# ── Top 10 Risk Cards ──────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Top 10 Highest-Risk Identities</h2></div>', unsafe_allow_html=True)

top10 = risk_df.nlargest(10, 'risk_score').copy()
top10['display_name'] = top10['name'].fillna(top10['identity_id'])

for _, row in top10.iterrows():
    lvl = row['risk_level']
    lvl_lower = lvl.lower()
    clr = COLOR_MAP.get(lvl, '#64748B')
    clr_rgba = _clr_to_rgba(clr)
    score = row['risk_score']
    score_pct = int(score)

    st.markdown(f"""
    <div class="risk-card {lvl_lower}">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;">
            <div>
                <div class="risk-card-name">{row['display_name']}</div>
                <div class="risk-card-meta">
                    <code style="font-size:0.7rem;">{row['identity_id']}</code>
                    &nbsp;·&nbsp; {row.get('department','—')} &nbsp;·&nbsp; {row.get('type','—')}
                    &nbsp;·&nbsp; {int(row.get('anomaly_count',0))} anomalies
                    &nbsp;·&nbsp; {int(row.get('privilege_count',0))} privileges
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:0.75rem;flex-shrink:0;">
                <div style="text-align:right;">
                    <div class="risk-score-pill" style="background:rgba({clr_rgba},0.12);
                         color:{clr};border:1px solid rgba({clr_rgba},0.3);">
                        {score:.0f} / 100
                    </div>
                    <div style="font-size:0.6rem;color:#64748B;margin-top:0.2rem;text-align:center;">{lvl}</div>
                </div>
                <div style="width:80px;">
                    <div style="height:5px;background:rgba(148,163,184,0.1);border-radius:3px;overflow:hidden;">
                        <div style="height:100%;width:{score_pct}%;background:{clr};
                                    border-radius:3px;box-shadow:0 0 4px {clr}66;"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ── Filters & Full Table ───────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Identity Risk Register</h2></div>', unsafe_allow_html=True)

col_f1, col_f2, col_f3 = st.columns([1, 1, 2])
with col_f1:
    selected_level = st.selectbox("Risk Level", ['All', 'Critical', 'High', 'Medium', 'Low'])
with col_f2:
    departments = ['All'] + sorted(risk_df['department'].dropna().unique().tolist())
    selected_dept = st.selectbox("Department", departments)
with col_f3:
    search_name = st.text_input("🔍 Search by name or ID", placeholder="Type a name, ID or department…")

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

st.caption(f"Showing **{len(filtered_df)}** of **{len(risk_df)}** identities · sorted by highest risk first")
st.dataframe(
    filtered_df[['identity_id', 'name', 'department', 'type', 'risk_score', 'risk_level', 'anomaly_count', 'privilege_count']]
        .sort_values(by='risk_score', ascending=False),
    use_container_width=True, height=320,
    column_config={
        'identity_id':     st.column_config.TextColumn('Identity ID',   width='small'),
        'name':            st.column_config.TextColumn('Name',          width='medium'),
        'department':      st.column_config.TextColumn('Department',    width='medium'),
        'type':            st.column_config.TextColumn('Type',          width='small'),
        'risk_score':      st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=100, format='%d %%'),
        'risk_level':      st.column_config.TextColumn('Level',         width='small'),
        'anomaly_count':   st.column_config.NumberColumn('Anomalies',   width='small'),
        'privilege_count': st.column_config.NumberColumn('Privileges',  width='small'),
    }
)

st.divider()

# ── Charts ─────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Risk Analytics</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Risk Score Distribution</div>', unsafe_allow_html=True)
    fig_hist = px.histogram(risk_df, x="risk_score", color="risk_level", nbins=25,
                             color_discrete_map=COLOR_MAP, opacity=0.85,
                             labels={'risk_score': 'Risk Score', 'count': 'Identities'})
    fig_hist.update_layout(**DARK_LAYOUT,
        legend=dict(font=dict(color=TEXT_COL, size=10), bgcolor='rgba(0,0,0,0)',
                    orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        xaxis=dict(gridcolor=GRID_COL, title='Risk Score', tickfont=dict(size=11, color=TEXT_COL)),
        yaxis=dict(gridcolor=GRID_COL, title='Identities', tickfont=dict(size=11, color=TEXT_COL)),
        margin=dict(t=30, b=20, l=10, r=10), bargap=0.03, height=280)
    fig_hist.update_traces(
        hovertemplate='Score: <b>%{x}</b><br>Count: <b>%{y}</b><extra></extra>',
        marker_line_color='rgba(255,255,255,0.1)', marker_line_width=0.5)
    st.plotly_chart(fig_hist, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Average Risk by Department</div>', unsafe_allow_html=True)
    dept_risk = risk_df.groupby('department')['risk_score'].mean().reset_index()
    dept_risk = dept_risk.sort_values('risk_score', ascending=True)
    dept_risk['color_cat'] = dept_risk['risk_score'].apply(
        lambda s: 'Critical' if s >= 80 else 'High' if s >= 60 else 'Medium' if s >= 30 else 'Low'
    )
    fig_dept = px.bar(dept_risk, x='risk_score', y='department', orientation='h',
                      color='color_cat', color_discrete_map=COLOR_MAP,
                      text=dept_risk['risk_score'].round(1),
                      labels={'risk_score': 'Avg Risk Score', 'department': ''})
    fig_dept.update_layout(**DARK_LAYOUT, showlegend=False,
        xaxis=dict(gridcolor=GRID_COL, title='Avg Risk Score', range=[0, 110],
                   tickfont=dict(size=11, color=TEXT_COL)),
        yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#F1F5F9')),
        margin=dict(t=10, b=20, l=10, r=40), height=280, bargap=0.3)
    fig_dept.update_traces(textposition='outside',
        textfont=dict(color='#F1F5F9', size=11, weight=600),
        hovertemplate='<b>%{y}</b><br>Avg Risk: <b>%{x:.1f}</b><extra></extra>',
        marker_line_color='rgba(0,0,0,0)')
    st.plotly_chart(fig_dept, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Risk by Type ───────────────────────────────────────────────────────────────
if 'type' in risk_df.columns:
    st.markdown('<div class="section-hdr"><h2>Risk Profile by Identity Type</h2></div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-wrapper"><div class="chart-hdr">Which identity types carry the most risk?</div>', unsafe_allow_html=True)
    type_risk = risk_df.groupby(['type', 'risk_level']).size().reset_index(name='count')
    fig_type = px.bar(type_risk, x='type', y='count', color='risk_level',
                      color_discrete_map=COLOR_MAP, barmode='stack',
                      labels={'type': 'Identity Type', 'count': 'Count', 'risk_level': 'Risk Level'})
    fig_type.update_layout(**DARK_LAYOUT,
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1,
                    font=dict(size=10, color=TEXT_COL), bgcolor='rgba(0,0,0,0)'),
        xaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=12, color='#F1F5F9')),
        yaxis=dict(gridcolor=GRID_COL, tickfont=dict(size=11, color=TEXT_COL)),
        bargap=0.35, height=260, margin=dict(t=30, b=20))
    fig_type.update_traces(
        hovertemplate='<b>%{x}</b> — %{data.name}<br>Count: <b>%{y}</b><extra></extra>',
        marker_line_color='rgba(255,255,255,0.1)', marker_line_width=0.5)
    st.plotly_chart(fig_type, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)
