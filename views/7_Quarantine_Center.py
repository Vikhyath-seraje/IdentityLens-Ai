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

# ── Title and Style Definitions ──────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Automated Response</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Quarantine Center</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Automated identity quarantine and access revocation across all platforms.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(230,0,40,0.06);border:1px solid rgba(230,0,40,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#E60028;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">AUTO RESPONSE</span>
</div>
</div>

<style>
@keyframes fadeSlideUp {
    from { opacity: 0; transform: translateY(15px); }
    to { opacity: 1; transform: translateY(0); }
}
.section-title h2 {
    font-size: 1.05rem;
    font-weight: 700;
    color: #1A1A1A;
    margin: 1.8rem 0 0.8rem;
    padding-bottom: 0.4rem;
    border-bottom: 2px solid #E60028;
    display: inline-block;
}
.kpi-insight {
    font-size: 0.72rem;
    color: #6B6B6B;
    margin-top: 0.25rem;
    line-height: 1.4;
}
.info-card {
    background: #FFFFFF;
    border: 1px solid #E0E0E0;
    border-radius: 8px;
    padding: 1.25rem 1.4rem;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    animation: fadeSlideUp 0.35s ease both;
    transition: all 0.2s ease-in-out;
}
.info-card:hover {
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    transform: translateY(-1px);
}
.info-card code {
    background: rgba(0, 0, 0, 0.04);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: monospace;
    color: #1A1A1A;
    font-size: 0.8rem;
}
.badge-active {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.6rem;
    background: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.25);
    border-radius: 100px;
    font-size: 0.68rem;
    font-weight: 700;
    color: #10B981;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}
.badge-quarantined {
    display: inline-flex;
    align-items: center;
    padding: 0.2rem 0.6rem;
    background: rgba(230, 0, 40, 0.08);
    border: 1px solid rgba(230, 0, 40, 0.25);
    border-radius: 100px;
    font-size: 0.68rem;
    font-weight: 700;
    color: #E60028;
    letter-spacing: 0.8px;
    text-transform: uppercase;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

# ── Data Loader ────────────────────────────────────────────────────────────
@st.cache_data(ttl=10)
def load_quarantine_data():
    conn = sqlite3.connect(DB_PATH)
    identities_df = IdentityResolver().get_resolved_identities()
    risk_df       = RiskEngine().calculate_risk_scores()
    merged_df     = risk_df.merge(
        identities_df[['identity_id', 'name', 'department', 'type']],
        on='identity_id', how='left'
    )

    quarantined_states = {}
    remediation = {}
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
                'tokens_revoked':    r['tokens_revoked'] or 0,
                'privileges_removed':r['privileges_removed'] or 0,
                'pre_risk_score':    r['pre_risk_score'],
                'pre_risk_level':    r['pre_risk_level'],
                'post_risk_score':   r['post_risk_score'],
                'post_risk_level':   r['post_risk_level'],
            }
    except Exception:
        pass

    merged_df['status']            = merged_df['identity_id'].map(lambda x: quarantined_states.get(x, 'active'))
    merged_df['tokens_revoked']    = merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('tokens_revoked', 0))
    merged_df['privileges_removed']= merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('privileges_removed', 0))

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

# ── System Demo Controls (Inline) ──────────────────────────────────────────
with st.expander("System Demo Controls", expanded=False):
    st.markdown("""
    <div style="font-size:0.85rem;color:#4A4A4A;margin-bottom:0.75rem;line-height:1.5;">
        Reset all identity records and quarantine states to re-run the security response demo cleanly.
    </div>
    """, unsafe_allow_html=True)
    if st.button("Reset Demo State", use_container_width=True):
        with st.spinner("Restoring original account data and clearing quarantine records…"):
            reset_demo_state()
            st.cache_data.clear()
        st.success("Demo state reset successfully.")
        st.rerun()

# ── KPIs ───────────────────────────────────────────────────────────────────
quarantined_df      = merged_df[merged_df['status'] == 'quarantined']
quarantined_count   = len(quarantined_df)
critical_neutralized= sum(
    1 for qid in quarantined_df['identity_id']
    if (remediation.get(qid, {}) or {}).get('pre_risk_level') == 'Critical'
)
tokens_revoked_total    = int(merged_df['tokens_revoked'].sum())
privileges_removed_total= int(merged_df['privileges_removed'].sum())

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Quarantined", quarantined_count)
    st.markdown('<div class="kpi-insight">Identities currently isolated across AD, Okta, & AWS</div>', unsafe_allow_html=True)
with col2:
    st.metric("Critical Neutralised", critical_neutralized)
    st.markdown('<div class="kpi-insight">Active high-risk threats successfully mitigated</div>', unsafe_allow_html=True)
with col3:
    st.metric("Tokens Revoked", tokens_revoked_total)
    st.markdown('<div class="kpi-insight">Access sessions invalidated globally</div>', unsafe_allow_html=True)
with col4:
    st.metric("Privileges Removed", privileges_removed_total)
    st.markdown('<div class="kpi-insight">Admin & privileged group roles revoked</div>', unsafe_allow_html=True)

st.divider()

# ── Monitored Identities Table ─────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>High-Risk Identities & Remediation Status</h2></div>', unsafe_allow_html=True)

col_f1, col_f2 = st.columns(2)
with col_f1:
    filter_status = st.selectbox("Filter by Status:", ["All", "Active/Normal", "Quarantined"])
with col_f2:
    filter_risk   = st.selectbox("Filter by Risk Level:", ["All", "Critical", "High", "Medium", "Low"])

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
    use_container_width=True, height=300,
    column_config={
        'identity_id':       st.column_config.TextColumn('Identity ID',  width='small'),
        'name':              st.column_config.TextColumn('Name',          width='medium'),
        'department':        st.column_config.TextColumn('Dept',          width='small'),
        'type':              st.column_config.TextColumn('Type',          width='small'),
        'risk_score':        st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=100, format='%d'),
        'risk_level':        st.column_config.TextColumn('Level',         width='small'),
        'status':            st.column_config.TextColumn('Status',        width='small'),
        'tokens_revoked':    st.column_config.NumberColumn('Tokens',      width='small'),
        'privileges_removed':st.column_config.NumberColumn('Privs',       width='small'),
    }
)

st.divider()

# ── Identity Profile & Controls ────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Details & Remediation Controls</h2></div>', unsafe_allow_html=True)

if display_df.empty:
    st.info("No identities match the current filters.")
else:
    def _fmt(ident):
        row = display_df[display_df['identity_id'] == ident]
        if row.empty:
            return ident
        status = row['status'].values[0].upper()
        name   = row['name'].values[0]
        return f"{ident}  ·  {name}  ({status})"

    selected_id = st.selectbox("Choose an identity for details and actions:", display_df['identity_id'].tolist(), format_func=_fmt)

    if selected_id:
        user_row     = merged_df[merged_df['identity_id'] == selected_id].iloc[0]
        policy_check = check_quarantine_rules(selected_id)
        remed        = remediation.get(selected_id, {})
        is_quarantined = user_row['status'] == 'quarantined'

        col_details, col_actions = st.columns([2, 1])

        with col_details:
            st.markdown(f"""
            <div class="info-card">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#6B6B6B;margin-bottom:0.8rem;font-weight:700;">IDENTITY PROFILE</div>
                <div style="font-size:1.20rem;font-weight:800;color:#1A1A1A;margin-bottom:0.4rem;">{user_row['name']}</div>
                <div style="font-size:0.82rem;color:#4A4A4A;line-height:1.6;">
                    <code>{selected_id}</code>
                    &nbsp;&nbsp;<code>{user_row['type']}</code>
                    &nbsp;&nbsp;<strong>Department:</strong> {user_row['department']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Platform accounts
            conn = sqlite3.connect(DB_PATH)
            ad_acc    = conn.execute("SELECT status, role   FROM ad_accounts   WHERE identity_id = ?", (selected_id,)).fetchone()
            aws_acc   = conn.execute("SELECT status, policy FROM aws_accounts  WHERE identity_id = ?", (selected_id,)).fetchone()
            okta_acc  = conn.execute("SELECT status, role   FROM okta_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
            token_count = conn.execute("SELECT COUNT(*) FROM api_tokens WHERE identity_id = ?", (selected_id,)).fetchone()[0]
            conn.close()

            st.markdown('<div style="font-size:0.85rem;font-weight:700;color:#1A1A1A;margin:1.2rem 0 0.6rem;">Platform Connection Status</div>', unsafe_allow_html=True)
            col_ad, col_aws, col_okta = st.columns(3)
            
            def platform_status_badge(status_val):
                s = str(status_val).lower() if status_val else ''
                if s in ['active', 'enabled']:
                    return f'<span class="badge-active">{status_val}</span>'
                elif s in ['quarantined', 'disabled', 'revoked']:
                    return f'<span class="badge-quarantined">{status_val}</span>'
                else:
                    return f'<span style="color:#6B6B6B;font-weight:600;">{status_val or "—"}</span>'

            with col_ad:
                st.markdown(f"""
                <div class="info-card" style="padding:0.9rem 1.1rem;height:100%;">
                    <div style="font-size:0.72rem;color:#6B6B6B;margin-bottom:0.4rem;font-weight:700;">ACTIVE DIRECTORY</div>
                    <div style="font-size:0.85rem;margin-bottom:0.3rem;">Status: {platform_status_badge(ad_acc[0] if ad_acc else None)}</div>
                    <div style="font-size:0.82rem;color:#4A4A4A;">Role: <code>{ad_acc[1] if ad_acc and ad_acc[1] else '—'}</code></div>
                </div>
                """, unsafe_allow_html=True)
            with col_aws:
                st.markdown(f"""
                <div class="info-card" style="padding:0.9rem 1.1rem;height:100%;">
                    <div style="font-size:0.72rem;color:#6B6B6B;margin-bottom:0.4rem;font-weight:700;">AWS IAM</div>
                    <div style="font-size:0.85rem;margin-bottom:0.3rem;">Status: {platform_status_badge(aws_acc[0] if aws_acc else None)}</div>
                    <div style="font-size:0.82rem;color:#4A4A4A;">Policy: <code>{aws_acc[1] if aws_acc and aws_acc[1] else '—'}</code></div>
                </div>
                """, unsafe_allow_html=True)
            with col_okta:
                st.markdown(f"""
                <div class="info-card" style="padding:0.9rem 1.1rem;height:100%;">
                    <div style="font-size:0.72rem;color:#6B6B6B;margin-bottom:0.4rem;font-weight:700;">OKTA</div>
                    <div style="font-size:0.85rem;margin-bottom:0.3rem;">Status: {platform_status_badge(okta_acc[0] if okta_acc else None)}</div>
                    <div style="font-size:0.82rem;color:#4A4A4A;">Role: <code>{okta_acc[1] if okta_acc and okta_acc[1] else '—'}</code></div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown(f"""
            <div style="font-size:0.85rem;color:#4A4A4A;margin:0.8rem 0;padding-left:0.25rem;">
                Active API Tokens: <strong style="color:#1A1A1A;">{token_count}</strong>
            </div>
            """, unsafe_allow_html=True)

            # Risk before/after chart
            if is_quarantined and remed:
                st.markdown('<div style="font-size:0.85rem;font-weight:700;color:#1A1A1A;margin:1.2rem 0 0.5rem;">Risk Reduction: Before → After Quarantine</div>', unsafe_allow_html=True)
                pre_score  = remed.get('pre_risk_score') or 0
                post_score = remed.get('post_risk_score') or 0
                pre_level  = remed.get('pre_risk_level') or '—'
                post_level = remed.get('post_risk_level') or '—'
                
                fig_risk = go.Figure()
                fig_risk.add_trace(go.Bar(
                    x=['Before Quarantine', 'After Quarantine'],
                    y=[pre_score, post_score],
                    text=[f"{pre_score} ({pre_level})", f"{post_score} ({post_level})"],
                    textposition='outside',
                    marker_color=['#E60028', '#007A4C'],
                    width=[0.35, 0.35],
                    hovertemplate='<b>%{x}</b><br>Risk Score: %{y}<extra></extra>',
                ))
                fig_risk.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(family='Inter, -apple-system, sans-serif', size=11, color='#1A1A1A'),
                    height=240,
                    showlegend=False,
                    yaxis=dict(
                        range=[0, 115],
                        title='Risk Score',
                        gridcolor='#E0E0E0',
                        zeroline=True,
                        zerolinecolor='#E0E0E0',
                    ),
                    xaxis=dict(
                        gridcolor='rgba(0,0,0,0)',
                    ),
                    margin=dict(t=30, b=10, l=10, r=10),
                )
                st.plotly_chart(fig_risk, use_container_width=True, config={'displayModeBar': False})

            # Policy rules
            st.markdown('<div style="font-size:0.85rem;font-weight:700;color:#1A1A1A;margin:1.2rem 0 0.6rem;">Matching Policy Rules</div>', unsafe_allow_html=True)
            if policy_check['eligible']:
                for rule in policy_check['rules']:
                    st.error(f"Policy Violation: **{rule}**")
            else:
                st.success("No automatic quarantine policy violations matched.")

        with col_actions:
            with st.container(border=True):
                st.markdown('<div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#6B6B6B;margin-bottom:0.8rem;font-weight:700;">REMEDIATION CONTROLS</div>', unsafe_allow_html=True)

                if is_quarantined:
                    st.warning("QUARANTINED — All access paths severed.")
                    st.markdown(f"""
                    **Mitigation Summary:**
                    * Tokens revoked: **{remed.get('tokens_revoked', 0)}**
                    * Privileges removed: **{remed.get('privileges_removed', 0)}**
                    """)
                    if st.button("Release from Quarantine", type="primary", use_container_width=True):
                        with st.spinner("Reversing quarantine and restoring previous access state…"):
                            res = release_identity(selected_id)
                        st.success(res)
                        st.cache_data.clear()
                        st.rerun()
                else:
                    if not policy_check['eligible']:
                        st.info("No automatic rules matched. Manual quarantine is available for active incident response.")
                    else:
                        st.success(f"Eligible for quarantine\n\nScore: **{policy_check['score']}** / Level: **{policy_check['level']}**")

                    if st.button("Initiate Quarantine", type="primary", use_container_width=True):
                        with st.spinner("Executing quarantine across AD, AWS IAM, and Okta…"):
                            res = quarantine_identity(selected_id, force=not policy_check['eligible'])
                        st.success(res)
                        st.cache_data.clear()
                        st.rerun()

st.divider()

# ── Audit Trail ────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Remediation Audit Trail</h2></div>', unsafe_allow_html=True)
if not audit_df.empty:
    action_filter = st.multiselect(
        "Filter by action type:",
        options=sorted(audit_df['Action'].unique()),
        default=[],
        placeholder="All actions shown…"
    )
    trail = audit_df if not action_filter else audit_df[audit_df['Action'].isin(action_filter)]
    st.dataframe(trail, use_container_width=True, height=280)
else:
    st.info("No quarantine or release actions have been executed yet.")

st.markdown('</div>', unsafe_allow_html=True)
