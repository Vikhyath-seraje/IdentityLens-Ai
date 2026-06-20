import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.anomaly_detection import AnomalyDetectionEngine
from models.isolation_forest import MLModel

st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Threat Detection</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Anomaly Detection</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Dual-layer engine combining rule-based heuristics with Isolation Forest ML.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(201,125,0,0.06);border:1px solid rgba(201,125,0,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#C97D00;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">AI + RULE ENGINE</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
@st.cache_data
def load_rule_anomalies():
    engine = AnomalyDetectionEngine()
    return engine.detect_anomalies()

@st.cache_data
def load_ml_anomalies():
    model = MLModel()
    results = model.train_and_predict()
    return results[results['anomaly_score'] == -1]

# ── Tabs for two detection modes ───────────────────────────────────────────
tab1, tab2 = st.tabs(["📋  Rule-Based Anomalies", "🤖  ML Anomalies (Isolation Forest)"])

with tab1:
    rule_anomalies = load_rule_anomalies()

    if not rule_anomalies.empty:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🚨 Total Anomalies", len(rule_anomalies))
        with col2:
            st.metric("🔖 Unique Types", rule_anomalies['anomaly_type'].nunique())
        with col3:
            st.metric("🆔 Affected Identities", rule_anomalies['identity_id'].nunique())

        st.divider()

        col_chart, col_table_selector = st.columns([1, 1])

        with col_chart:
            type_counts = rule_anomalies['anomaly_type'].value_counts().reset_index()
            type_counts.columns = ['Anomaly Type', 'Count']
            fig = px.bar(
                type_counts, x='Count', y='Anomaly Type', orientation='h',
                color='Count', color_continuous_scale='Oranges',
                text='Count', title="Anomalies by Type"
            )
            fig.update_layout(
                paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
                font_color='#1A1A1A', title_font_color='#1A1A1A', title_font_size=13,
                coloraxis_showscale=False, showlegend=False,
                xaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
                yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#4A4A4A')),
                margin=dict(t=40, b=10, l=10, r=40),
            )
            fig.update_traces(textposition='outside', textfont_color='#1A1A1A')
            st.plotly_chart(fig, use_container_width=True)

        with col_table_selector:
            selected_type = st.selectbox(
                "Filter by anomaly type:",
                ['All'] + sorted(rule_anomalies['anomaly_type'].unique().tolist())
            )
            display_anomalies = rule_anomalies if selected_type == 'All' else rule_anomalies[rule_anomalies['anomaly_type'] == selected_type]
            st.caption(f"Showing **{len(display_anomalies)}** anomalies")

        st.markdown('<div class="section-title"><h2>Anomaly Records</h2></div>', unsafe_allow_html=True)
        st.dataframe(
            display_anomalies,
            use_container_width=True,
            height=320,
            column_config={
                'identity_id':   st.column_config.TextColumn('Identity ID',    width='small'),
                'anomaly_type':  st.column_config.TextColumn('Anomaly Type',   width='medium'),
                'description':   st.column_config.TextColumn('Description',    width='large'),
            }
        )
    else:
        st.success("✅ No rule-based anomalies detected. System posture is clean.")

with tab2:
    st.markdown("""
    <div class="info-card">
        <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:0.6rem;">HOW IT WORKS</div>
        <p style="font-size:0.875rem;color:#94a3b8;margin:0;">
        The Isolation Forest model flags identities with anomalous patterns in 
        <strong style="color:#e2e8f0;">dormancy days</strong>, 
        <strong style="color:#e2e8f0;">role changes</strong>, 
        <strong style="color:#e2e8f0;">privilege counts</strong>, and 
        <strong style="color:#e2e8f0;">API token age</strong> — without requiring labelled data.
        </p>
    </div>
    """, unsafe_allow_html=True)

    ml_anomalies = load_ml_anomalies()

    if not ml_anomalies.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("🤖 ML-Detected Anomalies", len(ml_anomalies))
        with col2:
            avg_decision = ml_anomalies['anomaly_decision_function'].mean()
            st.metric("📉 Avg Decision Score", round(float(avg_decision), 3))

        st.markdown('<div class="section-title"><h2>ML Anomaly Records</h2></div>', unsafe_allow_html=True)
        display_cols = [c for c in ['identity_id', 'num_platforms', 'privilege_count', 'max_token_age', 'failed_logins', 'anomaly_decision_function'] if c in ml_anomalies.columns]
        st.dataframe(
            ml_anomalies[display_cols],
            use_container_width=True,
            height=340,
            column_config={
                'identity_id':             st.column_config.TextColumn('Identity ID',       width='medium'),
                'num_platforms':           st.column_config.NumberColumn('Platforms',        width='small'),
                'privilege_count':         st.column_config.ProgressColumn('Privileges',    min_value=0, max_value=int(ml_anomalies['privilege_count'].max()) if len(ml_anomalies) else 1, format='%d'),
                'max_token_age':           st.column_config.NumberColumn('Max Token Age',   width='small'),
                'failed_logins':           st.column_config.NumberColumn('Failed Logins',   width='small'),
                'anomaly_decision_function': st.column_config.NumberColumn('Isolation Score', format='%.4f', width='medium'),
            }
        )

        # Scatter of key features
        if 'privilege_count' in ml_anomalies.columns and 'failed_logins' in ml_anomalies.columns:
            st.markdown('<div class="section-title"><h2>Feature Scatter</h2></div>', unsafe_allow_html=True)
            fig_scatter = px.scatter(
                ml_anomalies, x='privilege_count', y='failed_logins',
                color='anomaly_decision_function', size_max=15,
                color_continuous_scale='RdYlGn_r',
                hover_data=['identity_id'],
                labels={'privilege_count': 'Privilege Count', 'failed_logins': 'Failed Logins'},
                title="Privilege Count vs Failed Logins (colour = isolation score)"
            )
            fig_scatter.update_layout(
                paper_bgcolor='rgba(255,255,255,0)', plot_bgcolor='rgba(255,255,255,0)',
                font_color='#1A1A1A', title_font_color='#1A1A1A', title_font_size=13,
                xaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
                yaxis=dict(gridcolor='rgba(0,0,0,0.07)'),
                margin=dict(t=40, b=20),
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
    else:
        st.success("✅ ML model detected no anomalies in the current dataset.")
