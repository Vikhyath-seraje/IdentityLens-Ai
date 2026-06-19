import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import json
from backend.terraform_manager import TerraformManager

st.title("🏗️ AWS Infrastructure Manager")
st.markdown("Deploy and manage the automated Terraform IAM environment directly from IdentityLens.")

manager = TerraformManager()

# Status Check
st.subheader("Environment Status")
out = manager.get_terraform_output()
if out and 'users' in out:
    st.success("✅ Environment is currently **DEPLOYED**.")
    with st.expander("View Terraform Outputs", expanded=False):
        st.json(out)
else:
    st.warning("⚠️ Environment is currently **NOT DEPLOYED** or no outputs found.")

st.divider()

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("### Deploy")
    st.caption("Provision all IAM users, groups, roles, and resources defined in Terraform.")
    if st.button("🚀 Deploy Environment", use_container_width=True, type="primary"):
        with st.spinner("Running `terraform apply`... This may take a minute."):
            try:
                logs = manager.deploy_environment()
                st.success("Deployment successful!")
                with st.expander("Deployment Logs"):
                    st.code(logs)
                st.rerun()
            except Exception as e:
                st.error(f"Deployment failed: {e}")

with col2:
    st.markdown("### Sync & Refresh")
    st.caption("Sync Terraform state to local DB and refresh live AWS drift via Boto3.")
    if st.button("🔄 Refresh AWS Data", use_container_width=True):
        with st.spinner("Syncing local database and querying AWS APIs..."):
            sync_res = manager.sync_aws_identities()
            boto_res = manager.refresh_aws_environment()
            st.success(sync_res)
            st.info(boto_res)

with col3:
    st.markdown("### Destroy")
    st.caption("Tear down all provisioned AWS resources. Use carefully.")
    if st.button("💥 Destroy Environment", use_container_width=True):
        with st.spinner("Running `terraform destroy`..."):
            try:
                logs = manager.destroy_environment()
                st.success("Destruction successful!")
                with st.expander("Destruction Logs"):
                    st.code(logs)
                st.rerun()
            except Exception as e:
                st.error(f"Destruction failed: {e}")
