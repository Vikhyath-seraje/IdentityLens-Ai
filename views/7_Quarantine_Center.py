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

DARK_BG  = '#0F172A'
CARD_BG  = '#1E293B'
TEXT_COL = '#94A3B8'
FONT_FAM = 'Inter, sans-serif'
GRID_COL = 'rgba(148,163,184,0.08)'

st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
@keyframes pulseGlow {
    0%,100%{ box-shadow:0 0 8px rgba(239,68,68,0.3); }
    50%{ box-shadow:0 0 20px rgba(239,68,68,0.6); }
}
.qc-page-hdr {
    display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
    padding-bottom:1.2rem;border-bottom:1px solid rgba(148,163,184,0.1);margin-bottom:1.5rem;
}
.section-hdr {
    display:flex;align-items:center;gap:0.75rem;margin:1.75rem 0 1rem;
}
.section-hdr h2 {
    font-size:0.82rem !important;font-weight:700 !important;color:#F1F5F9 !important;
    margin:0 !important;text-transform:uppercase;letter-spacing:0.8px;
}
.section-hdr::after { content:'';flex:1;height:1px;background:rgba(148,163,184,0.1); }
.qc-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.qc-kpi:hover { border-color:rgba(148,163,184,0.22);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.qc-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.qc-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1; }
.qc-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.info-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.2rem 1.4rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    animation:fadeIn 0.35s ease both;transition:all 0.2s ease;
}
.info-card:hover { border-color:rgba(148,163,184,0.18);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.chart-wrapper {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1rem 0.5rem;transition:all 0.25s ease;
}
.chart-wrapper:hover { border-color:rgba(148,163,184,0.18); }
.badge-active {
    display:inline-flex;align-items:center;gap:0.3rem;
    padding:0.2rem 0.65rem;
    background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);
    border-radius:100px;font-size:0.65rem;font-weight:700;color:#22C55E;
    letter-spacing:0.5px;text-transform:uppercase;
}
.badge-quarantined {
    display:inline-flex;align-items:center;gap:0.3rem;
    padding:0.2rem 0.65rem;
    background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.3);
    border-radius:100px;font-size:0.65rem;font-weight:700;color:#EF4444;
    letter-spacing:0.5px;text-transform:uppercase;
    animation:pulseGlow 2s infinite;
}
.platform-mini {
    background:rgba(15,23,42,0.6);border:1px solid rgba(148,163,184,0.1);
    border-radius:8px;padding:0.7rem 0.9rem;height:100%;
}
.split-label {
    font-size:0.62rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;
    margin-bottom:0.5rem;
}
.actions-panel {
    background:rgba(15,23,42,0.7);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.2rem 1.4rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

st.markdown("""
<div class="qc-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#EF4444;margin-bottom:0.3rem;">Automated Response</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Quarantine Center</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Automated identity quarantine and access revocation across all platforms.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#EF4444;
                letter-spacing:1px;text-transform:uppercase;animation:pulseGlow 2s infinite;">🔒 AUTO RESPONSE</span>
</div>
""", unsafe_allow_html=True)

# ── Data Loader ────────────────────────────────────────────────────────────────
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
                'tokens_revoked':     r['tokens_revoked'] or 0,
                'privileges_removed': r['privileges_removed'] or 0,
                'pre_risk_score':     r['pre_risk_score'],
                'pre_risk_level':     r['pre_risk_level'],
                'post_risk_score':    r['post_risk_score'],
                'post_risk_level':    r['post_risk_level'],
            }
    except Exception:
        pass

    merged_df['status']             = merged_df['identity_id'].map(lambda x: quarantined_states.get(x, 'active'))
    merged_df['tokens_revoked']     = merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('tokens_revoked', 0))
    merged_df['privileges_removed'] = merged_df['identity_id'].map(lambda x: remediation.get(x, {}).get('privileges_removed', 0))

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

# ── Demo Controls ──────────────────────────────────────────────────────────────
with st.expander("⚙️ System Demo Controls", expanded=False):
    st.markdown('<div style="font-size:0.82rem;color:#94A3B8;margin-bottom:0.75rem;">Reset all identity records and quarantine states to re-run the security response demo cleanly.</div>', unsafe_allow_html=True)
    if st.button("🔄 Reset Demo State", width="stretch"):
        with st.spinner("Restoring original account data and clearing quarantine records…"):
            reset_demo_state()
            st.cache_data.clear()
        st.success("Demo state reset successfully.")
        st.rerun()

# ── KPIs ───────────────────────────────────────────────────────────────────────
quarantined_df       = merged_df[merged_df['status'] == 'quarantined']
quarantined_count    = len(quarantined_df)
critical_neutralized = sum(
    1 for qid in quarantined_df['identity_id']
    if (remediation.get(qid, {}) or {}).get('pre_risk_level') == 'Critical'
)
tokens_revoked_total    = int(merged_df['tokens_revoked'].sum())
privileges_removed_total= int(merged_df['privileges_removed'].sum())

col1, col2, col3, col4 = st.columns(4)
kpi_data = [
    (col1, "Quarantined",          quarantined_count,        "#EF4444", "Identities currently isolated"),
    (col2, "Critical Neutralised", critical_neutralized,      "#22C55E", "High-risk threats mitigated"),
    (col3, "Tokens Revoked",       tokens_revoked_total,      "#3B82F6", "Sessions invalidated globally"),
    (col4, "Privileges Removed",   privileges_removed_total,  "#F97316", "Admin roles revoked"),
]
for col, lbl, val, clr, sub in kpi_data:
    with col:
        st.markdown(f"""
        <div class="qc-kpi">
            <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                        background:{clr};box-shadow:0 0 10px {clr}44;"></div>
            <div class="qc-kpi-lbl">{lbl}</div>
            <div class="qc-kpi-val" style="color:{clr};">{val}</div>
            <div class="qc-kpi-sub">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

st.divider()

# ── Monitored Identities Table ─────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>High-Risk Identities & Remediation Status</h2></div>', unsafe_allow_html=True)

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
    width="stretch", height=280,
    column_config={
        'identity_id':        st.column_config.TextColumn('Identity ID',  width='small'),
        'name':               st.column_config.TextColumn('Name',         width='medium'),
        'department':         st.column_config.TextColumn('Dept',         width='small'),
        'type':               st.column_config.TextColumn('Type',         width='small'),
        'risk_score':         st.column_config.ProgressColumn('Risk Score', min_value=0, max_value=100, format='%d'),
        'risk_level':         st.column_config.TextColumn('Level',        width='small'),
        'status':             st.column_config.TextColumn('Status',       width='small'),
        'tokens_revoked':     st.column_config.NumberColumn('Tokens',     width='small'),
        'privileges_removed': st.column_config.NumberColumn('Privs',      width='small'),
    }
)

st.divider()

# ── Identity Detail & Controls ─────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Identity Details & Remediation Controls</h2></div>', unsafe_allow_html=True)

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

    selected_id = st.selectbox("Choose an identity:", display_df['identity_id'].tolist(), format_func=_fmt)

    if selected_id:
        user_row     = merged_df[merged_df['identity_id'] == selected_id].iloc[0]
        policy_check = check_quarantine_rules(selected_id)
        remed        = remediation.get(selected_id, {})
        is_quarantined = user_row['status'] == 'quarantined'

        col_details, col_actions = st.columns([2, 1])

        with col_details:
            initials = "".join([n[0].upper() for n in str(user_row['name']).split()[:2]])
            status_badge_html = (
                '<span class="badge-quarantined">🔒 QUARANTINED</span>'
                if is_quarantined
                else '<span class="badge-active">● ACTIVE</span>'
            )
            risk_clr = {'Critical':'#EF4444','High':'#F97316','Medium':'#EAB308','Low':'#22C55E'}.get(
                user_row['risk_level'], '#64748B')

            st.markdown(f"""
            <div class="info-card">
                <div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:1rem;">
                    <div style="width:44px;height:44px;border-radius:50%;flex-shrink:0;
                                background:linear-gradient(135deg,{'#EF4444' if is_quarantined else '#3B82F6'},
                                {'#991B1B' if is_quarantined else '#1D4ED8'});
                                display:flex;align-items:center;justify-content:center;
                                font-size:1rem;font-weight:800;color:white;">{initials}</div>
                    <div>
                        <div style="font-size:1.1rem;font-weight:800;color:#F1F5F9;">{user_row['name']}</div>
                        <div style="margin-top:0.2rem;">{status_badge_html}</div>
                    </div>
                </div>
                <div style="font-size:0.82rem;color:#94A3B8;line-height:1.8;">
                    <div><code>{selected_id}</code> &nbsp;·&nbsp; <code>{user_row['type']}</code>
                        &nbsp;·&nbsp; <strong style="color:#F1F5F9;">{user_row['department']}</strong>
                    </div>
                    <div style="margin-top:0.3rem;">
                        <strong style="color:#F1F5F9;">Risk Score:</strong>
                        <span style="color:{risk_clr};font-weight:700;">{user_row['risk_score']:.0f}/100 — {user_row['risk_level']}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Platform status
            conn = sqlite3.connect(DB_PATH)
            ad_acc   = conn.execute("SELECT status, role   FROM ad_accounts   WHERE identity_id = ?", (selected_id,)).fetchone()
            aws_acc  = conn.execute("SELECT status, policy FROM aws_accounts  WHERE identity_id = ?", (selected_id,)).fetchone()
            okta_acc = conn.execute("SELECT status, role   FROM okta_accounts WHERE identity_id = ?", (selected_id,)).fetchone()
            token_count = conn.execute("SELECT COUNT(*) FROM api_tokens WHERE identity_id = ?", (selected_id,)).fetchone()[0]
            conn.close()

            st.markdown('<div style="font-size:0.78rem;font-weight:700;color:#F1F5F9;margin:1.2rem 0 0.6rem;">Platform Connection Status</div>', unsafe_allow_html=True)
            col_ad, col_aws, col_okta = st.columns(3)

            def plat_badge(status_val):
                s = str(status_val).lower() if status_val else ''
                if s in ['active', 'enabled']:
                    return f'<span class="badge-active">● {status_val}</span>'
                elif s in ['quarantined', 'disabled', 'revoked']:
                    return f'<span class="badge-quarantined">🔒 {status_val}</span>'
                return f'<span style="color:#64748B;font-weight:600;">{status_val or "—"}</span>'

            for c, icon, plat_name, acc, detail_key in [
                (col_ad,   "🏢", "Active Directory", ad_acc,   'role'),
                (col_aws,  "☁️", "AWS IAM",          aws_acc,  'policy'),
                (col_okta, "🔐", "Okta",             okta_acc, 'role'),
            ]:
                with c:
                    detail_val = acc[1] if acc and acc[1] else '—'
                    st.markdown(f"""
                    <div class="platform-mini">
                        <div style="font-size:0.62rem;color:#64748B;margin-bottom:0.3rem;font-weight:700;
                                    text-transform:uppercase;letter-spacing:0.8px;">{icon} {plat_name}</div>
                        <div style="margin-bottom:0.2rem;">{plat_badge(acc[0] if acc else None)}</div>
                        <div style="font-size:0.75rem;color:#64748B;">
                            {detail_key.capitalize()}: <code style="font-size:0.7rem;">{detail_val[:18]}</code>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown(f'<div style="font-size:0.82rem;color:#94A3B8;margin:0.75rem 0;padding-left:0.25rem;">Active API Tokens: <strong style="color:#3B82F6;">{token_count}</strong></div>', unsafe_allow_html=True)

            # ── Before vs After Quarantine Split Visualization ─────────────────
            if is_quarantined and remed:
                st.markdown('<div class="section-hdr" style="margin-top:1rem;"><h2>Before vs After Quarantine</h2></div>', unsafe_allow_html=True)

                pre_score  = remed.get('pre_risk_score') or 0
                post_score = remed.get('post_risk_score') or 0
                pre_level  = remed.get('pre_risk_level') or '—'
                post_level = remed.get('post_risk_level') or '—'
                reduction  = pre_score - post_score

                col_b, col_a = st.columns(2)

                with col_b:
                    st.markdown(f'<div class="chart-wrapper"><div class="split-label" style="color:#EF4444;">⬆ BEFORE QUARANTINE</div>', unsafe_allow_html=True)
                    fig_b = go.Figure()
                    fig_b.add_trace(go.Indicator(
                        mode="gauge+number",
                        value=pre_score,
                        number=dict(font=dict(size=24, color='#EF4444', family=FONT_FAM), suffix="/100"),
                        gauge={
                            'axis': {'range':[0,100],'tickcolor':'#475569','tickfont':dict(size=8,color=TEXT_COL)},
                            'bar':  {'color':'#EF4444','thickness':0.2},
                            'bgcolor': CARD_BG, 'borderwidth': 0,
                            'steps': [
                                {'range':[0,25],'color':'rgba(34,197,94,0.06)'},
                                {'range':[25,50],'color':'rgba(234,179,8,0.06)'},
                                {'range':[50,75],'color':'rgba(249,115,22,0.06)'},
                                {'range':[75,100],'color':'rgba(239,68,68,0.08)'},
                            ],
                            'threshold':{'line':{'color':'#EF4444','width':2},'thickness':0.85,'value':pre_score}
                        },
                        title=dict(text=f"<span style='font-size:11px;color:{TEXT_COL}'>{pre_level} Risk</span>",
                                   font=dict(size=11,color='#F1F5F9',family=FONT_FAM))
                    ))
                    fig_b.update_layout(paper_bgcolor=DARK_BG,font=dict(family=FONT_FAM),
                        height=200,margin=dict(t=60,b=10,l=20,r=20))
                    st.plotly_chart(fig_b, width="stretch")
                    st.markdown('</div>', unsafe_allow_html=True)

                with col_a:
                    st.markdown(f'<div class="chart-wrapper"><div class="split-label" style="color:#22C55E;">⬇ AFTER QUARANTINE</div>', unsafe_allow_html=True)
                    fig_a = go.Figure()
                    fig_a.add_trace(go.Indicator(
                        mode="gauge+number",
                        value=post_score,
                        number=dict(font=dict(size=24, color='#22C55E', family=FONT_FAM), suffix="/100"),
                        gauge={
                            'axis': {'range':[0,100],'tickcolor':'#475569','tickfont':dict(size=8,color=TEXT_COL)},
                            'bar':  {'color':'#22C55E','thickness':0.2},
                            'bgcolor': CARD_BG, 'borderwidth': 0,
                            'steps': [
                                {'range':[0,25],'color':'rgba(34,197,94,0.08)'},
                                {'range':[25,50],'color':'rgba(234,179,8,0.06)'},
                                {'range':[50,75],'color':'rgba(249,115,22,0.06)'},
                                {'range':[75,100],'color':'rgba(239,68,68,0.06)'},
                            ],
                            'threshold':{'line':{'color':'#22C55E','width':2},'thickness':0.85,'value':post_score}
                        },
                        title=dict(text=f"<span style='font-size:11px;color:{TEXT_COL}'>{post_level} Risk</span>",
                                   font=dict(size=11,color='#F1F5F9',family=FONT_FAM))
                    ))
                    fig_a.update_layout(paper_bgcolor=DARK_BG,font=dict(family=FONT_FAM),
                        height=200,margin=dict(t=60,b=10,l=20,r=20))
                    st.plotly_chart(fig_a, width="stretch")
                    st.markdown('</div>', unsafe_allow_html=True)

                st.markdown(f"""
                <div style="display:flex;gap:1rem;margin-top:0.5rem;">
                    <div style="flex:1;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);
                                border-radius:10px;padding:0.7rem 1rem;text-align:center;">
                        <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Risk Reduction</div>
                        <div style="font-size:1.4rem;font-weight:800;color:#22C55E;">↓ {reduction:.1f} pts</div>
                    </div>
                    <div style="flex:1;background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.2);
                                border-radius:10px;padding:0.7rem 1rem;text-align:center;">
                        <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Tokens Revoked</div>
                        <div style="font-size:1.4rem;font-weight:800;color:#3B82F6;">{int(remed.get('tokens_revoked',0))}</div>
                    </div>
                    <div style="flex:1;background:rgba(249,115,22,0.08);border:1px solid rgba(249,115,22,0.2);
                                border-radius:10px;padding:0.7rem 1rem;text-align:center;">
                        <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;">Privileges Removed</div>
                        <div style="font-size:1.4rem;font-weight:800;color:#F97316;">{int(remed.get('privileges_removed',0))}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Policy rules
            st.markdown('<div style="font-size:0.78rem;font-weight:700;color:#F1F5F9;margin:1.2rem 0 0.5rem;">Matching Policy Rules</div>', unsafe_allow_html=True)
            if policy_check['eligible']:
                for rule in policy_check['rules']:
                    st.error(f"Policy Violation: **{rule}**")
            else:
                st.success("No automatic quarantine policy violations matched.")

        with col_actions:
            st.markdown('<div class="actions-panel">', unsafe_allow_html=True)
            st.markdown('<div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:1rem;font-weight:700;">REMEDIATION CONTROLS</div>', unsafe_allow_html=True)

            if is_quarantined:
                st.markdown(f"""
                <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);
                            border-radius:8px;padding:0.75rem;margin-bottom:0.75rem;font-size:0.82rem;color:#94A3B8;">
                    <div style="color:#EF4444;font-weight:700;margin-bottom:0.4rem;">🔒 QUARANTINED</div>
                    All access paths severed across AD, AWS & Okta.<br>
                    <span style="color:#F1F5F9;">Tokens revoked: <strong>{remed.get('tokens_revoked',0)}</strong></span><br>
                    <span style="color:#F1F5F9;">Privileges removed: <strong>{remed.get('privileges_removed',0)}</strong></span>
                </div>
                """, unsafe_allow_html=True)
                if st.button("🔓 Release from Quarantine", type="primary", width="stretch"):
                    with st.spinner("Reversing quarantine and restoring access state…"):
                        res = release_identity(selected_id)
                    st.success(res)
                    st.cache_data.clear()
                    st.rerun()
            else:
                if policy_check['eligible']:
                    st.markdown(f"""
                    <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);
                                border-radius:8px;padding:0.75rem;margin-bottom:0.75rem;font-size:0.82rem;">
                        <div style="color:#EF4444;font-weight:700;margin-bottom:0.3rem;">⚡ Quarantine Eligible</div>
                        <div style="color:#94A3B8;">Score: <strong style="color:#F1F5F9;">{policy_check['score']}</strong>
                        · Level: <strong style="color:#F97316;">{policy_check['level']}</strong></div>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                    <div style="background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);
                                border-radius:8px;padding:0.75rem;margin-bottom:0.75rem;font-size:0.82rem;color:#94A3B8;">
                        No automatic rules matched. Manual quarantine available for active incident response.
                    </div>
                    """, unsafe_allow_html=True)

                if st.button("🔒 Initiate Quarantine", type="primary", width="stretch"):
                    with st.spinner("Executing quarantine across AD, AWS IAM, and Okta…"):
                        res = quarantine_identity(selected_id, force=not policy_check['eligible'])
                    st.success(res)
                    st.cache_data.clear()
                    st.rerun()

            st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# ── Audit Trail ────────────────────────────────────────────────────────────────
st.markdown('<div class="section-hdr"><h2>Remediation Audit Trail</h2></div>', unsafe_allow_html=True)
if not audit_df.empty:
    action_filter = st.multiselect(
        "Filter by action type:", options=sorted(audit_df['Action'].unique()),
        default=[], placeholder="All actions shown…"
    )
    trail = audit_df if not action_filter else audit_df[audit_df['Action'].isin(action_filter)]
    st.dataframe(trail, width="stretch", height=260)
else:
    st.info("No quarantine or release actions executed yet.")

st.markdown('</div>', unsafe_allow_html=True)
