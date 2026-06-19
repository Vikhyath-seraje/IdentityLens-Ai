import streamlit as st
import pandas as pd
from backend.identity_resolver import IdentityResolver
from backend.privilege_analyzer import PrivilegeAnalyzer

st.set_page_config(page_title="Identity Explorer", layout="wide")
st.title("Identity Explorer")

@st.cache_data
def load_identities():
    resolver = IdentityResolver()
    return resolver.get_resolved_identities()

@st.cache_data
def load_privileges():
    analyzer = PrivilegeAnalyzer()
    return analyzer.analyze_all_identities()

identities_df = load_identities()
privileges_df = load_privileges()

# Merge for exploration
explorer_df = identities_df.merge(privileges_df[['identity_id', 'effective_privileges', 'privilege_count']], on='identity_id', how='left')

st.markdown("Search and inspect individual identities, their roles, and privileges across the enterprise.")

search_query = st.text_input("Search by Identity ID, Name, or Department:")

if search_query:
    filtered_df = explorer_df[
        explorer_df['identity_id'].str.contains(search_query, case=False, na=False) |
        explorer_df['name'].str.contains(search_query, case=False, na=False) |
        explorer_df['department'].str.contains(search_query, case=False, na=False)
    ]
else:
    filtered_df = explorer_df

st.dataframe(
    filtered_df[['identity_id', 'name', 'type', 'department', 'ad_user', 'aws_user', 'okta_login', 'privilege_count']],
    use_container_width=True
)

st.subheader("Deep Dive")
selected_identity = st.selectbox("Select an Identity to inspect:", filtered_df['identity_id'].tolist())

if selected_identity:
    identity_data = filtered_df[filtered_df['identity_id'] == selected_identity].iloc[0]
    
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Name:** {identity_data['name']}")
        st.write(f"**Type:** {identity_data['type']}")
        st.write(f"**Department:** {identity_data['department']}")
        
    with col2:
        st.write(f"**AD Account:** {identity_data['ad_user']} (Status: {identity_data['ad_status']})")
        st.write(f"**AWS Account:** {identity_data['aws_user']} (Status: {identity_data['aws_status']})")
        st.write(f"**Okta Account:** {identity_data['okta_login']} (Status: {identity_data['okta_status']})")
        
    st.write("**Effective Privileges:**")
    st.write(", ".join(identity_data['effective_privileges']) if isinstance(identity_data['effective_privileges'], list) else "None")
