import streamlit as st
import pandas as pd
import sqlite3
import datetime
import json
from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine
from backend.quarantine_engine import quarantine_identity, release_identity, check_quarantine_rules

DB_PATH = 'database/identitylens.db'

st.set_page_config(
    page_title="Identity Quarantine Center",
    page_icon="",
    layout="wide",
)

# Custom Styling to match dashboard theme
st.markdown("""
<style>
    /* Main header styling */
    .quarantine-header {
        background: linear-gradient(135deg, #1e1b4b, #311042, #450a0a);
        padding: 2rem 2.5rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        color: white;
        border: 1px solid rgba(239, 68, 68, 0.2);
    }
    .quarantine-header h1 {
        font-size: 2.4rem;
        margin: 0;
        font-weight: 700;
        letter-spacing: -0.5px;
    }
    .quarantine-header p {
        opacity: 0.85;
        font-size: 1.1rem;
        margin-top: 0.3rem;
    }
    /* Section headers */
    .section-header {
        color: #ccd6f6;
        border-left: 4px solid #f87171;
        padding-left: 12px;
        margin-top: 1.5rem;
        margin-bottom: 0.8rem;
    }
    /* Status indicators */
    .status-badge {
        padding: 4px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .status-quarantined {
        background-color: rgba(239, 68, 68, 0.15);
        color: #ef4444;
        border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .status-active {
        background-color: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="quarantine-header">
    <h1>Identity Quarantine Center</h1>
    <p>Automated isolation & remediation engine for high-risk compromised identities</p>
</div>
""", unsafe_allow_html=True)

# Helper to load all necessary data
@st.cache_data(ttl=120)
def load_quarantine_data():
    conn = sqlite3.connect(DB_PATH)
    
    # Resolved identities
    resolver = IdentityResolver()
    identities_df = resolver.get_resolved_identities()
    
    # Risk info
    risk_engine = RiskEngine()
    risk_df = risk_engine.calculate_risk_scores()
    
    # Merge
    merged_df = risk_df.merge(
        identities_df[['identity_id', 'name', 'department', 'type']],
        on='identity_id', how='left'
    )
    
    # Check quarantine state of each identity based on the last record in quarantine_records
    quarantined_states = {}
    try:
        recs = conn.execute("""
            SELECT identity_id, status 
            FROM (
                SELECT identity_id, status, MAX(timestamp) 
                FROM quarantine_records 
                GROUP BY identity_id
            )
        """).fetchall()
        quarantined_states = {r[0]: r[1] for r in recs}
    except Exception:
        pass
    
    merged_df['status'] = merged_df['identity_id'].map(lambda x: quarantined_states.get(x, 'active'))
    
    # Audit Logs from quarantine records
    audit_df = pd.DataFrame()
    try:
        audit_df = pd.read_sql_query("""
            SELECT id, identity_id, timestamp, status 
            FROM quarantine_records 
            ORDER BY timestamp DESC
        """, conn)
    except Exception:
        pass
        
    conn.close()
    return merged_df, audit_df

merged_df, audit_df = load_quarantine_data()

@st.cache_data(ttl=120)
def _check_quarantine_rules_cached(identity_id: str) -> dict:
    """Cached wrapper to avoid re-running RiskEngine + AnomalyDetection on every rerun."""
    return check_quarantine_rules(identity_id)

# ── KPI Cards ─────────────────────────────────────────────────────────
kpi1, kpi2, kpi3, kpi4 = st.columns(4)

total_identities = len(merged_df)
quarantined_count = len(merged_df[merged_df['status'] == 'quarantined'])
critical_count = len(merged_df[merged_df['risk_level'] == 'Critical'])
eligible_count = sum(merged_df['identity_id'].map(lambda x: _check_quarantine_rules_cached(x)['eligible']))

kpi1.metric("Total Monitored", total_identities)
kpi2.metric("Quarantined", quarantined_count)
kpi3.metric("Critical Risk", critical_count)
kpi4.metric("Quarantine Eligible", eligible_count)

st.divider()

# ── Main Layout: Table and Control Panel ─────────────────────────────
st.markdown('<h3 class="section-header">Monitored Identities & Remediation Status</h3>', unsafe_allow_html=True)

# Filters
col_f1, col_f2 = st.columns(2)
with col_f1:
    filter_status = st.selectbox("Filter by Status:", ["All", "Active/Normal", "Quarantined"])
with col_f2:
    filter_risk = st.selectbox("Filter by Risk Level:", ["All", "Critical", "High", "Medium", "Low"])

display_df = merged_df.copy()
if filter_status == "Active/Normal":
    display_df = display_df[display_df['status'] != 'quarantined']
elif filter_status == "Quarantined":
    display_df = display_df[display_df['status'] == 'quarantined']

if filter_risk != "All":
    display_df = display_df[display_df['risk_level'] == filter_risk]

# Select target identity
st.dataframe(
    display_df[['identity_id', 'name', 'department', 'type', 'risk_score', 'risk_level', 'status']].sort_values('risk_score', ascending=False),
    width="stretch",
    height=300
)

st.subheader("Select Identity to Manage")
selected_id = st.selectbox(
    "Choose an identity profile for action details:",
    display_df['identity_id'].tolist(),
    format_func=lambda x: f"{x} - {display_df[display_df['identity_id'] == x]['name'].values[0]} ({display_df[display_df['identity_id'] == x]['status'].values[0].upper()})" if not display_df[display_df['identity_id'] == x].empty else x
)

if selected_id:
    user_row = merged_df[merged_df['identity_id'] == selected_id].iloc[0]
    
    # Check policy eligibility rules
    policy_check = _check_quarantine_rules_cached(selected_id)
    
    col_details, col_actions = st.columns([2, 1])
    
    with col_details:
        st.markdown(f"### Identity Profile: **{user_row['name']}**")
        st.markdown(f"**Identity ID:** `{selected_id}` | **Type:** `{user_row['type']}` | **Department:** `{user_row['department']}`")
        
        # Display platform accounts status
        conn = sqlite3.connect(DB_PATH)
        ad_acc = conn.execute("SELECT status, role, last_login FROM ad_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
        aws_acc = conn.execute("SELECT policy, last_login FROM aws_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
        okta_acc = conn.execute("SELECT status, role, last_login FROM okta_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
        tokens = conn.execute("SELECT token_id, age_days FROM api_tokens WHERE identity_id = ?", (selected_id,)).fetchall()
        conn.close()
        
        st.markdown("#### Platform Connection Status")
        col_ad, col_aws, col_okta = st.columns(3)
        
        with col_ad:
            st.markdown("**Active Directory**")
            if ad_acc:
                st.write(f"Status: `{ad_acc[0]}`")
                st.write(f"Role: `{ad_acc[1]}`")
            else:
                st.write("No AD Account Linked")
                
        with col_aws:
            st.markdown("**AWS IAM**")
            if aws_acc:
                st.write(f"Policy: `{aws_acc[0]}`")
            else:
                st.write("No AWS Account Linked")
                
        with col_okta:
            st.markdown("**Okta**")
            if okta_acc:
                st.write(f"Status: `{okta_acc[0]}`")
                st.write(f"Role: `{okta_acc[1]}`")
            else:
                st.write("No Okta Account Linked")
                
        # API Tokens list
        st.markdown("#### Linked API Tokens")
        if tokens:
            for t in tokens:
                st.write(f"- Token ID: `{t[0]}` (Age: {t[1]} days)")
        else:
            st.info("No active API tokens found for this identity.")

        st.markdown("#### Matching Policy Evaluation Rules")
        if policy_check['eligible']:
            for rule in policy_check['rules']:
                st.error(f"Policy Violation Match: **{rule}**")
        else:
            st.success("No Quarantine Policy Violations Matched")

    with col_actions:
        st.markdown("### Remediation Controls")
        
        is_quarantined = user_row['status'] == 'quarantined'
        
        if is_quarantined:
            st.warning("This identity is currently QUARANTINED. All access paths have been severed.")
            
            # Workflow Checklist when Quarantined
            st.markdown("#### Quarantine Execution Status")
            st.markdown("- [x] AD account state set to `Quarantined`")
            st.markdown("- [x] AWS account state set to `Quarantined`")
            st.markdown("- [x] Okta account state set to `Quarantined`")
            st.markdown("- [x] Revoked all API tokens")
            st.markdown("- [x] Staged administrator roles stripped")
            st.markdown("- [x] Quarantine audit record compiled")
            st.markdown("- [x] Dynamic Risk score recalculation completed")
            
            if st.button("Release from Quarantine", type="primary"):
                with st.spinner("Reversing quarantine and restoring previous state configurations..."):
                    res = release_identity(selected_id)
                    st.success(res)
                    st.rerun()
        else:
            if not policy_check['eligible']:
                st.info("This identity does not trigger any of the automatic quarantine rules. However, you can force quarantine if manual incident response protocols dictate.")
            
            # Workflow Checklist when Active
            st.markdown("#### Action Checklist")
            st.markdown("- [ ] Disable Active Directory login")
            st.markdown("- [ ] Deactivate AWS IAM policies")
            st.markdown("- [ ] Terminate active Okta sessions")
            st.markdown("- [ ] Revoke active API tokens")
            st.markdown("- [ ] Remove high-risk administrative privileges")
            st.markdown("- [ ] Broadcast security event logs")
            st.markdown("- [ ] Refresh risk metrics")
            
            if st.button("Initiate Quarantine Action", type="primary"):
                # Force policy check if needed or just execute
                with st.spinner("Executing Quarantine protocols across AD, AWS, and Okta platforms..."):
                    # Temporarily allow force-quarantine if not matching rules (for custom manual quarantine)
                    if not policy_check['eligible']:
                        # Inject a dummy check bypass by updating eligibility context or running directly
                        # Let's override to allow analysts manual overrides
                        conn = sqlite3.connect(DB_PATH)
                        snapshot = {}
                        ad = conn.execute("SELECT * FROM ad_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
                        snapshot['ad'] = dict(ad) if ad else None
                        aws = conn.execute("SELECT * FROM aws_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
                        snapshot['aws'] = dict(aws) if aws else None
                        okta = conn.execute("SELECT * FROM okta_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
                        snapshot['okta'] = dict(okta) if okta else None
                        tokens = conn.execute("SELECT * FROM api_tokens WHERE identity_id = ?", (selected_id,)).fetchall()
                        snapshot['tokens'] = [dict(t) for t in tokens]
                        
                        ts = datetime.datetime.utcnow().isoformat() + 'Z'
                        conn.execute("INSERT INTO quarantine_records (identity_id, timestamp, pre_quarantine_state, status) VALUES (?,?,?,?)",
                                     (selected_id, ts, json.dumps(snapshot), 'quarantined'))
                        conn.execute("UPDATE ad_accounts SET status = 'Quarantined' WHERE identity_id = ?", (selected_id,))
                        conn.execute("UPDATE aws_accounts SET policy = 'Quarantined' WHERE identity_id = ?", (selected_id,))
                        conn.execute("UPDATE okta_accounts SET status = 'Quarantined' WHERE identity_id = ?", (selected_id,))
                        conn.execute("DELETE FROM api_tokens WHERE identity_id = ?", (selected_id,))
                        conn.execute("UPDATE ad_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'", (selected_id,))
                        conn.execute("UPDATE aws_accounts SET policy = NULL WHERE identity_id = ? AND policy LIKE '%Admin%'", (selected_id,))
                        conn.execute("UPDATE okta_accounts SET role = NULL WHERE identity_id = ? AND role LIKE '%Admin%'", (selected_id,))
                        conn.commit()
                        conn.close()
                        st.success(f"Identity {selected_id} successfully quarantined (manual override).")
                    else:
                        res = quarantine_identity(selected_id)
                        st.success(res)
                    st.rerun()

st.divider()

# ── Audit Trail ──────────────────────────────────────────────────────
st.markdown('<h3 class="section-header">Remediation Engine Audit Trail</h3>', unsafe_allow_html=True)
if not audit_df.empty:
    st.dataframe(
        audit_df.rename(columns={"timestamp": "Execution Time", "status": "Action Taken"}),
        width="stretch",
        height=250
    )
else:
    st.info("No quarantine or release actions have been executed yet.")
