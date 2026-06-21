import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver

st.set_page_config(page_title="Executive Overview", layout="wide")
st.title("Executive Overview")

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

# Top KPIs
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Identities", summary['total_identities'])
col2.metric("Correlated Identities (AD+AWS+Okta)", summary['has_all_three_platforms'])
col3.metric("Critical Risk Identities", len(risk_df[risk_df['risk_level'] == 'Critical']))
col4.metric("High Risk Identities", len(risk_df[risk_df['risk_level'] == 'High']))

st.divider()

# Visualizations
col_charts_1, col_charts_2 = st.columns(2)

with col_charts_1:
    st.subheader("Identity Types Distribution")
    type_df = pd.DataFrame(list(summary['types'].items()), columns=['Type', 'Count'])
    fig_types = px.pie(type_df, values='Count', names='Type', hole=0.4, color_discrete_sequence=px.colors.sequential.Teal)
    st.plotly_chart(fig_types, width="stretch")

with col_charts_2:
    st.subheader("Risk Level Distribution")
    risk_counts = risk_df['risk_level'].value_counts().reset_index()
    risk_counts.columns = ['Risk Level', 'Count']
    # Ensure order for colors
    color_map = {'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'}
    fig_risk = px.bar(risk_counts, x='Risk Level', y='Count', color='Risk Level', color_discrete_map=color_map)
    st.plotly_chart(fig_risk, width="stretch")

st.subheader("Identities by Department")
dept_df = pd.DataFrame(list(summary['departments'].items()), columns=['Department', 'Count'])
fig_dept = px.bar(dept_df, x='Department', y='Count', color='Department', color_discrete_sequence=px.colors.qualitative.Pastel)
st.plotly_chart(fig_dept, width="stretch")
