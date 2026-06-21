import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.anomaly_detection import AnomalyDetectionEngine, get_mitre_mapping
from models.isolation_forest import MLModel

# Severity color map for anomaly types
ANOMALY_SEVERITY_COLORS = {
    'SERVICE_ACCOUNT_COMPROMISE':           '#DC2626',
    'UNAUTHORIZED_PRIVILEGE_ESCALATION':    '#EA580C',
    'FIRST_TIME_SENSITIVE_ACCESS':         '#F59E0B',
    'OUTSIDE_NORMAL_ACTIVITY_WINDOW':      '#EAB308',
    'Privilege Escalation':                '#F97316',
    'Cross Platform Admin':                '#F97316',
    'Impossible Travel':                  '#F97316',
    'Token Abuse':                         '#EF4444',
    'Credential Sharing':                 '#EF4444',
    'Service Account Abuse':              '#F97316',
    'Nested Escalation':                  '#F97316',
    'Expired Privilege':                  '#EAB308',
    'Dormant Admin':                      '#EAB308',
    'Orphan Contractor':                  '#3B82F6',
    'Offboarding Gap':                    '#3B82F6',
    'Old API Token':                      '#64748B',
}

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

st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
.anom-page-hdr {
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
.anom-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.anom-kpi:hover { border-color:rgba(148,163,184,0.22);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.anom-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.anom-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1; }
.anom-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.chart-wrapper {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1rem 0.5rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.chart-wrapper:hover { border-color:rgba(148,163,184,0.18);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.how-it-works {
    background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);
    border-left:3px solid #3B82F6;border-radius:0 10px 10px 0;
    padding:1rem 1.2rem;margin-bottom:1rem;
    font-size:0.875rem;color:#94A3B8;line-height:1.6;
}
.insight-banner {
    padding:0.65rem 1rem;margin:0.8rem 0;border-radius:0 8px 8px 0;
    font-size:0.83rem;color:#94A3B8;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

st.markdown("""
<div class="anom-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#F97316;margin-bottom:0.3rem;">Threat Detection</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Anomaly Detection</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Dual-layer engine — rule-based heuristics combined with Isolation Forest ML model.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(249,115,22,0.1);border:1px solid rgba(249,115,22,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#F97316;
                letter-spacing:1px;text-transform:uppercase;">⚡ AI + RULE ENGINE</span>
</div>
""", unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_rule_anomalies():
    return AnomalyDetectionEngine().detect_anomalies()

def load_ml_anomalies():
    model = MLModel()
    results = model.train_and_predict()
    return results[results['anomaly_score'] == -1]

# ── Tabs ────────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs(["⚡ Rule-Based Anomalies", "🤖 ML Anomalies (Isolation Forest)"])

# ══════════════════════════════════════════════════════
# TAB 1 — RULE-BASED
# ══════════════════════════════════════════════════════
with tab1:
    rule_anomalies = load_rule_anomalies()

    if not rule_anomalies.empty:
        total_a      = len(rule_anomalies)
        unique_ids   = rule_anomalies['identity_id'].nunique()
        unique_types = rule_anomalies['anomaly_type'].nunique()
        most_common  = rule_anomalies['anomaly_type'].value_counts().index[0]

        col1, col2, col3, col4 = st.columns(4)
        kpi_data = [
            (col1, "Total Anomalies",    total_a,     "#EF4444", "All flagged events"),
            (col2, "Affected Identities", unique_ids,  "#F97316", "Unique accounts impacted"),
            (col3, "Anomaly Types",      unique_types, "#EAB308", "Distinct categories"),
            (col4, "Top Issue",          most_common[:16] + "…" if len(most_common) > 16 else most_common,
                    "#3B82F6", "Most common anomaly"),
        ]
        for col, lbl, val, clr, sub in kpi_data:
            with col:
                st.markdown(f"""
                <div class="anom-kpi">
                    <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                                background:{clr};box-shadow:0 0 10px {clr}44;"></div>
                    <div class="anom-kpi-lbl">{lbl}</div>
                    <div class="anom-kpi-val" style="color:{clr};font-size:{'1.2rem' if len(str(val)) > 8 else '1.9rem'};">{val}</div>
                    <div class="anom-kpi-sub">{sub}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="insight-banner" style="background:rgba(249,115,22,0.06);border-left:3px solid #F97316;">
            ⚡ The rule engine detected <strong style="color:#F97316;">{total_a} anomalies</strong>
            across <strong style="color:#F1F5F9;">{unique_ids} identities</strong>.
            The most common issue is <strong style="color:#F97316;">'{most_common}'</strong> —
            review the records below and action high-priority cases first.
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        col_chart, col_controls = st.columns([3, 2])

        with col_chart:
            st.markdown('<div class="chart-wrapper"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem;">Anomalies by Type</div>', unsafe_allow_html=True)
            type_counts = rule_anomalies['anomaly_type'].value_counts().reset_index()
            type_counts.columns = ['Anomaly Type', 'Count']
            type_counts = type_counts.sort_values('Count', ascending=True)
            # Add severity color per anomaly type
            type_counts['bar_color'] = type_counts['Anomaly Type'].map(ANOMALY_SEVERITY_COLORS).fillna('#64748B')

            fig = go.Figure(go.Bar(
                x=type_counts['Count'],
                y=type_counts['Anomaly Type'],
                orientation='h',
                marker=dict(
                    color=type_counts['bar_color'],
                    line=dict(color='rgba(0,0,0,0)'),
                    opacity=0.9,
                ),
                text=type_counts['Count'],
                textposition='outside',
                textfont=dict(color='#F1F5F9', size=12, weight=700),
                hovertemplate='<b>%{y}</b><br>Count: <b>%{x}</b><extra></extra>',
            ))
            fig.update_layout(**DARK_LAYOUT,
                xaxis=dict(gridcolor=GRID_COL, title='', tickfont=dict(size=11, color=TEXT_COL)),
                yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#F1F5F9')),
                coloraxis_showscale=False,
                margin=dict(t=10, b=10, l=10, r=50),
                height=280, showlegend=False,
            )
            st.plotly_chart(fig, width="stretch")
            st.markdown('</div>', unsafe_allow_html=True)

        with col_controls:
            st.markdown('<div style="height:0.5rem;"></div>', unsafe_allow_html=True)
            selected_type = st.selectbox(
                "Filter records by anomaly type:",
                ['All'] + sorted(rule_anomalies['anomaly_type'].unique().tolist())
            )
            display_anomalies = (
                rule_anomalies if selected_type == 'All'
                else rule_anomalies[rule_anomalies['anomaly_type'] == selected_type]
            )
            st.caption(f"**{len(display_anomalies)}** anomaly records match your filter")

            mini_counts = rule_anomalies['anomaly_type'].value_counts().head(5).reset_index()
            mini_counts.columns = ['Type', 'Count']
            fig_mini = px.pie(mini_counts, values='Count', names='Type', hole=0.55,
                              color_discrete_sequence=['#EF4444','#F97316','#EAB308','#22C55E','#3B82F6'])
            fig_mini.update_layout(
                paper_bgcolor=DARK_BG, plot_bgcolor=DARK_BG,
                font=dict(family=FONT_FAM, color=TEXT_COL),
                height=190, showlegend=False,
                margin=dict(t=0, b=0, l=0, r=0),
                annotations=[dict(text='Top 5', x=0.5, y=0.5, font_size=11,
                                   showarrow=False, font_color=TEXT_COL)]
            )
            fig_mini.update_traces(
                textinfo='none',
                hovertemplate='<b>%{label}</b>: %{value}<extra></extra>',
                marker=dict(line=dict(color=DARK_BG, width=2))
            )
            st.plotly_chart(fig_mini, width="stretch")

        st.markdown('<div class="section-hdr"><h2>Anomaly Records</h2></div>', unsafe_allow_html=True)
        # Add MITRE ATT&CK info to the display
        display_anomalies = display_anomalies.copy()
        display_anomalies['MITRE Technique'] = display_anomalies['anomaly_type'].apply(
            lambda x: f"{get_mitre_mapping(x)['technique']} — {get_mitre_mapping(x)['name']}"
        )
        st.dataframe(
            display_anomalies,
            width="stretch", height=320,
            column_config={
                'identity_id':  st.column_config.TextColumn('Identity ID',  width='small'),
                'anomaly_type': st.column_config.TextColumn('Anomaly Type', width='medium'),
                'description':  st.column_config.TextColumn('Description',  width='large'),
            }
        )
    else:
        st.success("No rule-based anomalies detected. Your rule engine is not flagging any issues — the system posture looks clean.")

# ══════════════════════════════════════════════════════
# TAB 2 — ML ANOMALIES
# ══════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div class="how-it-works">
        <div style="font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;color:#3B82F6;
                    margin-bottom:0.5rem;font-weight:700;">How the ML Engine Works</div>
        The <strong style="color:#F1F5F9;">Isolation Forest</strong> model detects statistically unusual identities
        by analysing patterns in <strong style="color:#F1F5F9;">dormancy days</strong>,
        <strong style="color:#F1F5F9;">role changes</strong>,
        <strong style="color:#F1F5F9;">privilege counts</strong>, and
        <strong style="color:#F1F5F9;">API token age</strong> — all without needing labelled training data.
        It "isolates" anomalies by how few splits are needed to separate them from the rest of the dataset.
    </div>
    """, unsafe_allow_html=True)

    ml_anomalies = load_ml_anomalies()

    if not ml_anomalies.empty:
        avg_decision = ml_anomalies['anomaly_decision_function'].mean()

        col1, col2, col3 = st.columns(3)
        kpi_ml = [
            (col1, "ML-Flagged Identities", len(ml_anomalies),             "#EF4444", "Unusual behavioural patterns"),
            (col2, "Avg Isolation Score",   f"{round(float(avg_decision), 3)}", "#8B5CF6", "More negative = more anomalous"),
        ]
        if 'privilege_count' in ml_anomalies.columns:
            avg_priv = ml_anomalies['privilege_count'].mean()
            kpi_ml.append((col3, "Avg Privilege Count", f"{avg_priv:.1f}", "#F97316", "Among flagged identities"))

        for col, lbl, val, clr, sub in kpi_ml:
            with col:
                st.markdown(f"""
                <div class="anom-kpi">
                    <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                                background:{clr};box-shadow:0 0 10px {clr}44;"></div>
                    <div class="anom-kpi-lbl">{lbl}</div>
                    <div class="anom-kpi-val" style="color:{clr};">{val}</div>
                    <div class="anom-kpi-sub">{sub}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown('<div class="section-hdr"><h2>ML Anomaly Records</h2></div>', unsafe_allow_html=True)
        display_cols = [c for c in ['identity_id', 'num_platforms', 'privilege_count',
                                     'max_token_age', 'failed_logins', 'anomaly_decision_function']
                        if c in ml_anomalies.columns]
        max_priv = int(ml_anomalies['privilege_count'].max()) if 'privilege_count' in ml_anomalies.columns and len(ml_anomalies) else 1
        st.dataframe(
            ml_anomalies[display_cols],
            width="stretch", height=300,
            column_config={
                'identity_id':               st.column_config.TextColumn('Identity ID',    width='medium'),
                'num_platforms':             st.column_config.NumberColumn('Platforms',     width='small'),
                'privilege_count':           st.column_config.ProgressColumn('Privileges', min_value=0,
                                             max_value=max_priv, format='%d'),
                'max_token_age':             st.column_config.NumberColumn('Max Token Age', width='small'),
                'failed_logins':             st.column_config.NumberColumn('Failed Logins', width='small'),
                'anomaly_decision_function': st.column_config.NumberColumn('Isolation Score', format='%.4f', width='medium'),
            }
        )

        # Feature Scatter
        if 'privilege_count' in ml_anomalies.columns and 'failed_logins' in ml_anomalies.columns:
            st.markdown('<div class="section-hdr"><h2>Feature Scatter — Privilege vs Failed Logins</h2></div>', unsafe_allow_html=True)
            st.markdown('<div class="chart-wrapper"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem;">Each dot is an anomalous identity — colour shows how isolated it is</div>', unsafe_allow_html=True)

            ml_anomalies['plot_size'] = ml_anomalies['privilege_count'] + 2
            fig_scatter = px.scatter(
                ml_anomalies,
                x='privilege_count', y='failed_logins',
                color='anomaly_decision_function',
                size='plot_size', size_max=22,
                color_continuous_scale=[[0,'#22C55E'],[0.5,'#EAB308'],[1,'#EF4444']],
                hover_data=['identity_id'],
                labels={
                    'privilege_count': 'Privilege Count',
                    'failed_logins':   'Failed Logins',
                    'anomaly_decision_function': 'Isolation Score'
                },
            )
            fig_scatter.update_layout(**DARK_LAYOUT,
                coloraxis_colorbar=dict(
                    title=dict(text='Isolation<br>Score', font=dict(size=11, color=TEXT_COL)),
                    tickfont=dict(size=10, color=TEXT_COL),
                    bgcolor='rgba(0,0,0,0)',
                    thickness=12,
                ),
                xaxis=dict(gridcolor=GRID_COL, title='Privilege Count',
                           tickfont=dict(size=11, color=TEXT_COL), rangemode='nonnegative'),
                yaxis=dict(gridcolor=GRID_COL, title='Failed Logins',
                           tickfont=dict(size=11, color=TEXT_COL),
                           range=[-1, max(1, ml_anomalies['failed_logins'].max() + 1)]),
                margin=dict(t=10, b=20, l=10, r=20), height=340,
            )
            fig_scatter.update_traces(
                marker_line=dict(width=1.5, color=DARK_BG),
                hovertemplate='<b>%{customdata[0]}</b><br>Privileges: <b>%{x}</b><br>Failed Logins: <b>%{y}</b><br>Isolation Score: <b>%{marker.color:.4f}</b><extra></extra>',
            )
            st.plotly_chart(fig_scatter, width="stretch")
            st.markdown('</div>', unsafe_allow_html=True)

        # Isolation score distribution
        if 'anomaly_decision_function' in ml_anomalies.columns:
            st.markdown('<div class="section-hdr"><h2>Isolation Score Distribution</h2></div>', unsafe_allow_html=True)
            st.markdown('<div class="chart-wrapper"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem;">How extreme are the flagged anomalies? (more negative = more anomalous)</div>', unsafe_allow_html=True)
            fig_iso = px.histogram(
                ml_anomalies, x='anomaly_decision_function', nbins=20,
                color_discrete_sequence=['#8B5CF6'],
                labels={'anomaly_decision_function': 'Isolation Score', 'count': 'Count'}
            )
            fig_iso.update_layout(**DARK_LAYOUT,
                xaxis=dict(gridcolor=GRID_COL, title='Isolation Score', tickfont=dict(size=11, color=TEXT_COL)),
                yaxis=dict(gridcolor=GRID_COL, title='Number of Identities', tickfont=dict(size=11, color=TEXT_COL)),
                margin=dict(t=10, b=20, l=10, r=10), height=260, bargap=0.04,
            )
            fig_iso.update_traces(
                marker_opacity=0.85,
                marker_line_color='rgba(255,255,255,0.1)', marker_line_width=0.5,
                hovertemplate='Score range: <b>%{x}</b><br>Count: <b>%{y}</b><extra></extra>',
            )
            st.plotly_chart(fig_iso, width="stretch")
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.success("The ML model detected no anomalies in the current dataset — all identity behaviour looks within normal bounds.")

st.markdown('</div>', unsafe_allow_html=True)
