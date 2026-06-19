import streamlit as st
import pandas as pd
from backend.ai_engine import AIEngine
from backend.anomaly_detection import AnomalyDetectionEngine
from backend.identity_resolver import IdentityResolver

st.set_page_config(page_title="AI Remediation Center", layout="wide")
st.title("AI Remediation Center")

@st.cache_resource
def get_ai_engine():
    return AIEngine()

@st.cache_data
def get_anomalies_and_identities():
    anomaly_engine = AnomalyDetectionEngine()
    anomalies_df = anomaly_engine.detect_anomalies()
    
    resolver = IdentityResolver()
    identities_df = resolver.get_resolved_identities()
    
    return anomalies_df, identities_df

ai_engine = get_ai_engine()
anomalies_df, identities_df = get_anomalies_and_identities()

st.markdown("Use Generative AI to automatically generate remediation plans for detected anomalies.")

if anomalies_df.empty:
    st.success("No anomalies detected. System is secure.")
else:
    # Select an anomaly to remediate
    st.subheader("Select Anomaly to Remediate")
    
    # Merge for display
    display_df = anomalies_df.merge(identities_df[['identity_id', 'name', 'department']], on='identity_id', how='left')
    
    # Create options for dropdown
    options = display_df.apply(lambda x: f"[{x['anomaly_type']}] {x['name']} ({x['identity_id']})", axis=1).tolist()
    
    selected_option = st.selectbox("Detected Anomalies:", options)
    
    if selected_option:
        # Get the selected row
        index = options.index(selected_option)
        row = display_df.iloc[index]
        
        st.write(f"**Description:** {row['description']}")
        
        if st.button("Generate AI Remediation Plan"):
            with st.spinner("Analyzing risk and generating remediation plan using Gemini AI..."):
                identity_context = f"ID: {row['identity_id']}, Name: {row['name']}, Department: {row['department']}"
                anomaly_desc = row['description']
                
                remediation_plan = ai_engine.get_remediation(anomaly_desc, identity_context)
                
            st.markdown("### Suggested Remediation Plan")
            st.markdown(remediation_plan)
