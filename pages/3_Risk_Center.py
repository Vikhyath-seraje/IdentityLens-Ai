import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
from backend.risk_engine import RiskEngine
from backend.identity_resolver import IdentityResolver

st.title("Risk Center")

@st.cache_data
def load_risk_data():
    engine = RiskEngine()
    risk_df = engine.calculate_risk_scores()
    
    resolver = IdentityResolver()
    identities_df = resolver.get_resolved_identities()
    
    # Merge to get names and departments
    return risk_df.merge(identities_df[['identity_id', 'name', 'department', 'type']], on='identity_id', how='left')

risk_df = load_risk_data()

st.markdown("Overview of identity risks across the organization based on calculated risk scores.")

# Filter by Risk Level
selected_level = st.selectbox("Filter by Risk Level:", ['All', 'Critical', 'High', 'Medium', 'Low'])

if selected_level != 'All':
    filtered_df = risk_df[risk_df['risk_level'] == selected_level]
else:
    filtered_df = risk_df

st.dataframe(
    filtered_df[['identity_id', 'name', 'department', 'risk_score', 'risk_level', 'anomaly_count', 'privilege_count']].sort_values(by='risk_score', ascending=False),
    use_container_width=True
)

st.subheader("Risk Score Distribution")
fig_hist = px.histogram(risk_df, x="risk_score", color="risk_level", nbins=20, 
                        color_discrete_map={'Critical': 'red', 'High': 'orange', 'Medium': 'yellow', 'Low': 'green'})
st.plotly_chart(fig_hist, use_container_width=True)
