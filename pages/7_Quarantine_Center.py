import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sqlite3

from backend.identity_resolver import IdentityResolver
from backend.risk_engine import RiskEngine
from backend.quarantine_engine import (
    quarantine_identity, release_identity, check_quarantine_rules,
)
from database.init_db import reset_demo_state

DB_PATH = 'database/identitylens.db'

st.set_page_config(
    page_title="Identity Quarantine Center",
    page_icon="🛡️",
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
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="quarantine-header">
    <h1>🛡️ Identity Quarantine Engine</h1>
    <p>Automated isolation & remediation engine for high-risk compromised identities</p>
</div>
""", unsafe_allow_html=True)


# ── Data loaders ─────────────────────────────────────────────────────
@st.cache_data(ttl=10)
def load_quarantine_data():
    conn = sqlite3.connect(DB_PATH)

    # Resolved identities + risk info
    identities_df = IdentityResolver().get_resolved_identities()
    risk_df = RiskEngine().calculate_risk_scores()
    merged_df = risk_df.merge(
        identities_df[['identity_id', 'name', 'department', 'type']],
        on='identity_id', how='left'
    )

    # Latest quarantine status + remediation metrics per identity
    quarantined_states = {}
    remediation = {}  # identity_id -> {tokens_revoked, privileges_removed, pre/post risk}
    try:
        recs = pd.read_sql_query("""
            SELECT identity_id, status, tokens_revoked, privileges_removed,
                   pre_risk_score, pre_risk_level, post_risk_score, post_risk_level
            FROM (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY identity_id ORDER BY id DESC) AS rn
                FROM quarantine_records
            ) WHERE rn = 1
        """, conn)
        for _, r in recs.iterrows():
            quarantined_states[r['identity_id']] = r['status']
            remediation[r['identity_id']] = {
                'tokens_revoked': r['tokens_revoked'] or 0,
                'privileges_removed': r['privileges_removed'] or 0,
                'pre_risk_score': r['pre_risk_score'],
                'pre_risk_level': r['pre_risk_level'],
                'post_risk_score': r['post_risk_score'],
                'post_risk_level': r['post_risk_level'],
            }
    except Exception:
        pass

    merged_df['status'] = merged_df['identity_id'].map(lambda x: quarantined_states.get(x, 'active'))
    merged_df['tokens_revoked'] = merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('tokens_revoked', 0))
    merged_df['privileges_removed'] = merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('privileges_removed', 0))

    # Full audit trail (granular events from the audit table)
    audit_df = pd.DataFrame()
    try:
        audit_df = pd.read_sql_query("""
            SELECT timestamp AS "Execution Time", identity_id AS "Identity",
                   action AS "Action", platform AS "Platform", detail AS "Detail", run_id AS "Run ID"
            FROM quarantine_audit_events ORDER BY id DESC
        """, conn)
    except Exception:
        pass

    conn.close()
    return merged_df, remediation, audit_df


merged_df, remediation, audit_df = load_quarantine_data()

# ── Demo reset ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Demo Controls")
    st.caption("Reset all accounts and quarantine state to re-run the demo cleanly.")
    if st.button("♻️ Reset Demo State", use_container_width=True):
        with st.spinner("Restoring original account data and clearing quarantine records..."):
            reset_demo_state()
            st.cache_data.clear()
        st.success("Demo state reset.")
        st.rerun()

# ── KPI Cards ────────────────────────────────────────────────────────
quarantined_df = merged_df[merged_df['status'] == 'quarantined']
quarantined_count = len(quarantined_df)
critical_neutralized = sum(
    1 for qid in quarantined_df['identity_id']
    if (remediation.get(qid, {}) or {}).get('pre_risk_level') == 'Critical'
)
tokens_revoked_total = merged_df['tokens_revoked'].sum()
privileges_removed_total = merged_df['privileges_removed'].sum()

kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("🛑 Total Quarantined", quarantined_count)
kpi2.metric("🔴 Critical Risks Neutralized", critical_neutralized)
kpi3.metric("🔑 Tokens Revoked", int(tokens_revoked_total))
kpi4.metric("➖ Privileges Removed", int(privileges_removed_total))

st.divider()

# ── Monitored identities table ───────────────────────────────────────
st.markdown('<h3 class="section-header">High-Risk Identities & Remediation Status</h3>', unsafe_allow_html=True)

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

table_cols = ['identity_id', 'name', 'department', 'type', 'risk_score', 'risk_level',
              'status', 'tokens_revoked', 'privileges_removed']
st.dataframe(
    display_df[table_cols].sort_values('risk_score', ascending=False),
    use_container_width=True,
    height=300,
    column_config={
        'identity_id': st.column_config.TextColumn('Identity ID', width='small'),
        'name': st.column_config.TextColumn('Name', width='medium'),
        'risk_score': st.column_config.ProgressColumn('Risk', min_value=0, max_value=100, format='%d'),
        'risk_level': st.column_config.TextColumn('Level', width='small'),
        'status': st.column_config.TextColumn('Status', width='small'),
        'tokens_revoked': st.column_config.NumberColumn('Tokens', width='small'),
        'privileges_removed': st.column_config.NumberColumn('Privs', width='small'),
    }
)

# ── Identity profile + controls ──────────────────────────────────────
st.markdown('<h3 class="section-header">Identity Details & Remediation Controls</h3>', unsafe_allow_html=True)

if display_df.empty:
    st.info("No identities match the current filters.")
else:
    options = display_df['identity_id'].tolist()

    def _fmt(ident):
        row = display_df[display_df['identity_id'] == ident]
        if row.empty:
            return ident
        return f"{ident} - {row['name'].values[0]} ({row['status'].values[0].upper()})"

    selected_id = st.selectbox("Choose an identity profile for action details:", options, format_func=_fmt)

    if selected_id:
        user_row = merged_df[merged_df['identity_id'] == selected_id].iloc[0]
        policy_check = check_quarantine_rules(selected_id)
        remed = remediation.get(selected_id, {})
        is_quarantined = user_row['status'] == 'quarantined'

        col_details, col_actions = st.columns([2, 1])

        with col_details:
            st.markdown(f"### Identity Profile: **{user_row['name']}**")
            st.markdown(
                f"**Identity ID:** `{selected_id}` | **Type:** `{user_row['type']}` | "
                f"**Department:** `{user_row['department']}`"
            )

            # Platform accounts status
            conn = sqlite3.connect(DB_PATH)
            ad_acc = conn.execute("SELECT status, role FROM ad_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
            aws_acc = conn.execute("SELECT status, policy FROM aws_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
            okta_acc = conn.execute("SELECT status, role FROM okta_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
            token_count = conn.execute("SELECT COUNT(*) FROM api_tokens WHERE identity_id = ?", (selected_id,)).fetchone()[0]
            conn.close()

            st.markdown("#### Platform Connection Status")
            col_ad, col_aws, col_okta = st.columns(3)
            with col_ad:
                st.markdown("**Active Directory**")
                st.write(f"Status: `{ad_acc[0] if ad_acc else '—'}`")
                st.write(f"Role: `{ad_acc[1] if ad_acc and ad_acc[1] else '—'}`")
            with col_aws:
                st.markdown("**AWS IAM**")
                st.write(f"Status: `{aws_acc[0] if aws_acc else '—'}`")
                st.write(f"Policy: `{aws_acc[1] if aws_acc and aws_acc[1] else '—'}`")
            with col_okta:
                st.markdown("**Okta**")
                st.write(f"Status: `{okta_acc[0] if okta else '—'}`")
                st.write(f"Role: `{okta_acc[1] if okta and okta_acc[1] else '—'}`")
            st.markdown(f"**Active API Tokens:** `{token_count}`")

            # ── Before / After risk visualization ──
            if is_quarantined and remed:
                st.markdown("#### Risk Reduction (Before → After Quarantine)")
                pre_score = remed.get('pre_risk_score') or 0
                post_score = remed.get('post_risk_score') or 0
                pre_level = remed.get('pre_risk_level') or '—'
                post_level = remed.get('post_risk_level') or '—'
                fig_risk = go.Figure()
                fig_risk.add_trace(go.Bar(
                    x=['Before', 'After'],
                    y=[pre_score, post_score],
                    text=[f"{pre_score} ({pre_level})", f"{post_score} ({post_level})"],
                    textposition='outside',
                    marker_color=['#ef4444', '#10b981'],
                    width=[0.5, 0.5],
                ))
                fig_risk.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#ccd6f6', height=280, showlegend=False,
                    yaxis=dict(range=[0, 110], title='Risk Score', gridcolor='rgba(255,255,255,0.05)'),
                    margin=dict(t=20, b=20, l=10, r=10),
                )
                st.plotly_chart(fig_risk, use_container_width=True)

            st.markdown("#### Matching Policy Evaluation Rules")
            if policy_check['eligible']:
                for rule in policy_check['rules']:
                    st.error(f"🔴 Policy Violation Match: **{rule}**")
            else:
                st.success("🟢 No Quarantine Policy Violations Matched")

        with col_actions:
            st.markdown("### Remediation Controls")

            if is_quarantined:
                st.warning("⚠️ This identity is currently QUARANTINED. All access paths severed.")
                st.markdown(
                    f"- 🔑 Tokens revoked: **{remed.get('tokens_revoked', 0)}**\n"
                    f"- ➖ Admin privileges removed: **{remed.get('privileges_removed', 0)}**"
                )
                if st.button("🔓 Release from Quarantine", type="primary", use_container_width=True):
                    with st.spinner("Reversing quarantine and restoring previous state..."):
                        res = release_identity(selected_id)
                    st.success(res)
                    st.cache_data.clear()
                    st.rerun()
            else:
                if not policy_check['eligible']:
                    st.info("ℹ️ No automatic quarantine rules match, but manual quarantine is available for incident response.")
                else:
                    st.success(f"✅ Eligible for quarantine (score {policy_check['score']}/{policy_check['level']}).")

                if st.button("🛡️ Initiate Quarantine", type="primary", use_container_width=True):
                    with st.spinner("Executing quarantine across AD, AWS, and Okta..."):
                        res = quarantine_identity(selected_id, force=not policy_check['eligible'])
                    st.success(res)
                    st.cache_data.clear()
                    st.rerun()

st.divider()

# ── Audit Trail ──────────────────────────────────────────────────────
st.markdown('<h3 class="section-header">Remediation Audit Trail</h3>', unsafe_allow_html=True)
if not audit_df.empty:
    action_filter = st.multiselect(
        "Filter by action:",
        options=sorted(audit_df['Action'].unique()),
        default=[],
    )
    trail = audit_df if not action_filter else audit_df[audit_df['Action'].isin(action_filter)]
    st.dataframe(trail, use_container_width=True, height=280)
else:
    st.info("No quarantine or release actions have been executed yet.")
