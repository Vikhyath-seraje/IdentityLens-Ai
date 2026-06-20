import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.anomaly_detection import AnomalyDetectionEngine
from models.isolation_forest import MLModel

# ── Page header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Threat Detection</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Anomaly Detection</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Dual-layer engine — rule-based heuristics combined with Isolation Forest ML model.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(201,125,0,0.06);border:1px solid rgba(201,125,0,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#C97D00;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">AI + RULE ENGINE</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(14px)}
    to{opacity:1;transform:translateY(0)}
}
.chart-wrapper {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1rem 0.5rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    transition:box-shadow 0.25s;animation:fadeSlideUp 0.4s ease both;
}
.chart-wrapper:hover { box-shadow:0 6px 20px rgba(0,0,0,0.1); }
.anomaly-card {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1.2rem;margin-bottom:0.7rem;
    box-shadow:0 1px 4px rgba(0,0,0,0.05);
    transition:all 0.2s;animation:fadeSlideUp 0.35s ease both;
    border-left:4px solid #E60028;
}
.anomaly-card:hover { box-shadow:0 4px 14px rgba(0,0,0,0.1); transform:translateX(3px); }
.section-title h2 {
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}
.kpi-insight { font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4; }
.how-it-works {
    background:rgba(0,96,168,0.04);border:1px solid rgba(0,96,168,0.15);
    border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem;
    font-size:0.875rem;color:#4A4A4A;line-height:1.6;
}
.how-it-works strong { color:#0060A8; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_rule_anomalies():
    engine = AnomalyDetectionEngine()
    return engine.detect_anomalies()

def load_ml_anomalies():
    model = MLModel()
    results = model.train_and_predict()
    return results[results['anomaly_score'] == -1]

# ── Tabs ────────────────────────────────────────────────────────────────────────
tab1, tab2 = st.tabs([" Rule-Based Anomalies", " ML Anomalies (Isolation Forest)"])

# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — RULE-BASED
# ════════════════════════════════════════════════════════════════════════════════
with tab1:
    rule_anomalies = load_rule_anomalies()

    if not rule_anomalies.empty:
        total_a    = len(rule_anomalies)
        unique_ids = rule_anomalies['identity_id'].nunique()
        unique_types = rule_anomalies['anomaly_type'].nunique()
        most_common = rule_anomalies['anomaly_type'].value_counts().index[0]

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Anomalies", total_a)
            st.markdown('<div class="kpi-insight">All flagged events</div>', unsafe_allow_html=True)
        with col2:
            st.metric("Affected Identities", unique_ids)
            st.markdown('<div class="kpi-insight">Unique accounts impacted</div>', unsafe_allow_html=True)
        with col3:
            st.metric("Anomaly Types", unique_types)
            st.markdown('<div class="kpi-insight">Distinct categories</div>', unsafe_allow_html=True)
        with col4:
            st.metric("Top Issue", most_common[:20] + "…" if len(most_common) > 20 else most_common)
            st.markdown('<div class="kpi-insight">Most common anomaly</div>', unsafe_allow_html=True)

        st.markdown(f"""
        <div style="background:rgba(201,125,0,0.05);border:1px solid rgba(201,125,0,0.2);
                    border-radius:8px;padding:0.65rem 1rem;margin:0.8rem 0;font-size:0.83rem;color:#4A4A4A;">
            The rule engine detected <strong style="color:#C97D00">{total_a} anomalies</strong>
            across <strong>{unique_ids} identities</strong>.
            The most common issue is <strong style="color:#C97D00">'{most_common}'</strong> —
            review the records below and action high-priority cases first.
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        col_chart, col_controls = st.columns([3, 2])

        with col_chart:
            st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
            type_counts = rule_anomalies['anomaly_type'].value_counts().reset_index()
            type_counts.columns = ['Anomaly Type', 'Count']
            type_counts = type_counts.sort_values('Count', ascending=True)

            # Generate a warm palette for each anomaly type
            n = len(type_counts)
            oranges = px.colors.sequential.Oranges[max(1, 9 - n):9][::-1]

            fig = go.Figure(go.Bar(
                x=type_counts['Count'],
                y=type_counts['Anomaly Type'],
                orientation='h',
                marker=dict(
                    color=type_counts['Count'],
                    colorscale=[[0, '#FEF3C7'], [0.5, '#F59E0B'], [1, '#B45309']],
                    line=dict(color='rgba(0,0,0,0)'),
                    opacity=0.9,
                ),
                text=type_counts['Count'],
                textposition='outside',
                textfont=dict(color='#1A1A1A', size=12, weight=700),
                hovertemplate='<b>%{y}</b><br>Count: <b>%{x}</b><extra></extra>',
            ))
            fig.update_layout(
                title=dict(text="Anomalies by type — what's most common?",
                           font=dict(size=13, color='#4A4A4A', family='Inter, sans-serif')),
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Inter, sans-serif', color='#1A1A1A'),
                xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='', tickfont=dict(size=11)),
                yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#4A4A4A')),
                margin=dict(t=50, b=10, l=10, r=50),
                height=280,
            )
            st.plotly_chart(fig, use_container_width=True)
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

            # Mini pie chart of types
            mini_counts = rule_anomalies['anomaly_type'].value_counts().head(5).reset_index()
            mini_counts.columns = ['Type', 'Count']
            fig_mini = px.pie(mini_counts, values='Count', names='Type', hole=0.5,
                              color_discrete_sequence=['#E60028','#EA580C','#D97706','#16A34A','#0060A8'])
            fig_mini.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', height=160,
                margin=dict(t=0, b=0, l=0, r=0),
                showlegend=False,
                annotations=[dict(text='Top 5', x=0.5, y=0.5, font_size=11, showarrow=False, font_color='#6B6B6B')]
            )
            fig_mini.update_traces(textinfo='none', hovertemplate='<b>%{label}</b>: %{value}<extra></extra>')
            st.plotly_chart(fig_mini, use_container_width=True)

        st.markdown('<div class="section-title"><h2>Anomaly Records</h2></div>', unsafe_allow_html=True)
        st.dataframe(
            display_anomalies,
            use_container_width=True,
            height=320,
            column_config={
                'identity_id':   st.column_config.TextColumn('Identity ID',   width='small'),
                'anomaly_type':  st.column_config.TextColumn('Anomaly Type',  width='medium'),
                'description':   st.column_config.TextColumn('Description',   width='large'),
            }
        )
    else:
        st.success("No rule-based anomalies detected. Your rule engine is not flagging any issues — the system posture looks clean.")

# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — ML ANOMALIES
# ════════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("""
    <div class="how-it-works">
        <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#0060A8;
                    margin-bottom:0.5rem;font-weight:700;">How the ML Engine Works</div>
        The <strong>Isolation Forest</strong> model detects statistically unusual identities
        by analysing patterns in <strong>dormancy days</strong>, <strong>role changes</strong>,
        <strong>privilege counts</strong>, and <strong>API token age</strong> — all without needing
        labelled training data. It "isolates" anomalies by how few splits are needed to separate them
        from the rest of the dataset.
    </div>
    """, unsafe_allow_html=True)

    ml_anomalies = load_ml_anomalies()

    if not ml_anomalies.empty:
        avg_decision = ml_anomalies['anomaly_decision_function'].mean()

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("ML-Flagged Identities", len(ml_anomalies))
            st.markdown('<div class="kpi-insight">Unusual behavioural patterns</div>', unsafe_allow_html=True)
        with col2:
            st.metric("Avg Isolation Score", f"{round(float(avg_decision), 3)}")
            st.markdown('<div class="kpi-insight">More negative = more anomalous</div>', unsafe_allow_html=True)
        with col3:
            if 'privilege_count' in ml_anomalies.columns:
                avg_priv = ml_anomalies['privilege_count'].mean()
                st.metric("Avg Privilege Count", f"{avg_priv:.1f}")
                st.markdown('<div class="kpi-insight">Among flagged identities</div>', unsafe_allow_html=True)

        st.markdown('<div class="section-title"><h2>ML Anomaly Records</h2></div>', unsafe_allow_html=True)
        display_cols = [c for c in ['identity_id', 'num_platforms', 'privilege_count',
                                     'max_token_age', 'failed_logins', 'anomaly_decision_function']
                        if c in ml_anomalies.columns]
        st.dataframe(
            ml_anomalies[display_cols],
            use_container_width=True,
            height=300,
            column_config={
                'identity_id':               st.column_config.TextColumn('Identity ID',     width='medium'),
                'num_platforms':             st.column_config.NumberColumn('Platforms',      width='small'),
                'privilege_count':           st.column_config.ProgressColumn('Privileges',  min_value=0,
                                             max_value=int(ml_anomalies['privilege_count'].max()) if len(ml_anomalies) else 1,
                                             format='%d'),
                'max_token_age':             st.column_config.NumberColumn('Max Token Age',  width='small'),
                'failed_logins':             st.column_config.NumberColumn('Failed Logins',  width='small'),
                'anomaly_decision_function': st.column_config.NumberColumn('Isolation Score', format='%.4f', width='medium'),
            }
        )

        # ── Feature Scatter ──────────────────────────────────────────────────────
        if 'privilege_count' in ml_anomalies.columns and 'failed_logins' in ml_anomalies.columns:
            st.markdown('<div class="section-title"><h2>Feature Scatter — Privilege vs Failed Logins</h2></div>', unsafe_allow_html=True)
            st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

            # Ensure no points are invisible by giving a baseline size
            ml_anomalies['plot_size'] = ml_anomalies['privilege_count'] + 2

            fig_scatter = px.scatter(
                ml_anomalies,
                x='privilege_count', y='failed_logins',
                color='anomaly_decision_function',
                size='plot_size',
                size_max=22,
                color_continuous_scale='RdYlGn_r',
                hover_data=['identity_id'],
                labels={
                    'privilege_count': 'Privilege Count',
                    'failed_logins': 'Failed Logins',
                    'anomaly_decision_function': 'Isolation Score'
                },
                title="Each dot is an anomalous identity — colour shows how isolated it is"
            )
            fig_scatter.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Inter, sans-serif', color='#1A1A1A'),
                title_font=dict(size=13, color='#4A4A4A'),
                coloraxis_colorbar=dict(
                    title=dict(text='Isolation<br>Score', font=dict(size=11, color='#6B6B6B')),
                    tickfont=dict(size=10, color='#6B6B6B'),
                ),
                xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Privilege Count', tickfont=dict(size=11), rangemode='nonnegative'),
                yaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Failed Logins',   tickfont=dict(size=11),
                           range=[-1, max(1, ml_anomalies['failed_logins'].max() + 1)]),
                margin=dict(t=55, b=20, l=10, r=20),
                height=340,
            )
            fig_scatter.update_traces(
                marker_line=dict(width=1.5, color='rgba(255,255,255,0.7)'),
                hovertemplate='<b>%{customdata[0]}</b><br>Privileges: <b>%{x}</b><br>Failed Logins: <b>%{y}</b><br>Isolation Score: <b>%{marker.color:.4f}</b><extra></extra>',
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── Distribution of isolation scores ──────────────────────────────────
        if 'anomaly_decision_function' in ml_anomalies.columns:
            st.markdown('<div class="section-title"><h2>Isolation Score Distribution</h2></div>', unsafe_allow_html=True)
            st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

            fig_iso = px.histogram(
                ml_anomalies, x='anomaly_decision_function', nbins=20,
                color_discrete_sequence=['#E60028'],
                title="How extreme are the flagged anomalies? (more negative = more anomalous)",
                labels={'anomaly_decision_function': 'Isolation Score', 'count': 'Count'}
            )
            fig_iso.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font=dict(family='Inter, sans-serif', color='#1A1A1A'),
                title_font=dict(size=13, color='#4A4A4A'),
                xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Isolation Score', tickfont=dict(size=11)),
                yaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Number of Identities', tickfont=dict(size=11)),
                margin=dict(t=55, b=20, l=10, r=10),
                height=260,
                bargap=0.04,
            )
            fig_iso.update_traces(
                marker_opacity=0.8,
                marker_line_color='rgba(255,255,255,0.5)', marker_line_width=0.5,
                hovertemplate='Score range: <b>%{x}</b><br>Count: <b>%{y}</b><extra></extra>',
            )
            st.plotly_chart(fig_iso, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.success("The ML model detected no anomalies in the current dataset — all identity behaviour looks within normal bounds.")
