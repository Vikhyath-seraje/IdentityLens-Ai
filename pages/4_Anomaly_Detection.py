import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
from backend.anomaly_detection import AnomalyDetectionEngine
from models.isolation_forest import MLModel

st.title("Anomaly Detection Engine")

@st.cache_data
def load_rule_anomalies():
    engine = AnomalyDetectionEngine()
    return engine.detect_anomalies()

@st.cache_data
def load_ml_anomalies():
    model = MLModel()
    results = model.train_and_predict()
    # Filter only anomalous ones (-1)
    return results[results['anomaly_score'] == -1]

st.header("1. Rule-Based Anomalies")
rule_anomalies = load_rule_anomalies()

if not rule_anomalies.empty:
    st.write(f"Detected **{len(rule_anomalies)}** rule-based anomalies.")
    
    # Anomaly Type breakdown
    type_counts = rule_anomalies['anomaly_type'].value_counts().reset_index()
    type_counts.columns = ['Anomaly Type', 'Count']
    fig = px.bar(type_counts, x='Anomaly Type', y='Count', color='Anomaly Type')
    st.plotly_chart(fig, use_container_width=True)
    
    st.dataframe(rule_anomalies, use_container_width=True)
else:
    st.success("No rule-based anomalies detected.")

st.divider()

st.header("2. Machine Learning Anomalies (Isolation Forest)")
st.markdown("These identities have been flagged by the ML model due to unusual patterns in features such as dormancy days, role changes, privilege counts, and token age.")

ml_anomalies = load_ml_anomalies()

if not ml_anomalies.empty:
    st.write(f"Detected **{len(ml_anomalies)}** ML-based anomalies.")
    st.dataframe(
        ml_anomalies[['identity_id', 'num_platforms', 'privilege_count', 'max_token_age', 'failed_logins', 'anomaly_decision_function']],
        use_container_width=True
    )
else:
    st.success("No ML-based anomalies detected.")
