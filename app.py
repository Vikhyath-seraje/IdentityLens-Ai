import streamlit as st

st.set_page_config(
    page_title="IdentityLens AI",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("IdentityLens AI")
st.subheader("Enterprise Identity Security Analytics Platform")

st.markdown("""
Welcome to **IdentityLens AI**, a comprehensive cybersecurity platform designed to:
- **Correlate identities** across Active Directory, AWS IAM, and Okta.
- **Detect risky access patterns** and anomalies.
- **Calculate effective privileges** and risk scores.
- **Visualize attack paths** using interactive graphs.
- **Provide AI-generated remediation** recommendations.

Please navigate using the sidebar to explore the platform modules:
1. **Executive Overview**: High-level metrics and risk distribution.
2. **Identity Explorer**: Search and inspect individual identities across platforms.
3. **Risk Center**: View overall risk scores and critical identities.
4. **Anomaly Detection**: Analyze rule-based and ML-based anomalies.
5. **Attack Graph**: Visualize privilege escalation paths.
6. **AI Remediation Center**: Get AI-generated guidance for resolving identity risks.
""")

st.info("Ensure you have initialized the database using `python database/init_db.py` before exploring the modules.")
