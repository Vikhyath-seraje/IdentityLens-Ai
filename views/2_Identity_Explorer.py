import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
from backend.identity_resolver import IdentityResolver
from backend.privilege_analyzer import PrivilegeAnalyzer

st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Identity Management</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Identity Explorer</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Search, inspect, and analyse identities across Active Directory, AWS IAM, and Okta.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,96,168,0.06);border:1px solid rgba(0,96,168,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#0060A8;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">SEARCH & INVESTIGATE</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
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

explorer_df = identities_df.merge(
    privileges_df[['identity_id', 'effective_privileges', 'privilege_count']],
    on='identity_id', how='left'
)

# ── Search ─────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Search</h2></div>', unsafe_allow_html=True)

col_search, col_metric1, col_metric2 = st.columns([3, 1, 1])
with col_search:
    search_query = st.text_input("🔍  Search by Identity ID, Name, or Department", placeholder="e.g. alice, finance, EMP-001 …")
with col_metric1:
    st.metric("Total Identities", len(explorer_df))
with col_metric2:
    st.metric("Privileged", int(explorer_df['privilege_count'].fillna(0).gt(5).sum()))

if search_query:
    filtered_df = explorer_df[
        explorer_df['identity_id'].str.contains(search_query, case=False, na=False) |
        explorer_df['name'].str.contains(search_query, case=False, na=False) |
        explorer_df['department'].str.contains(search_query, case=False, na=False)
    ]
    st.caption(f'Showing **{len(filtered_df)}** result(s) for "{search_query}"')
else:
    filtered_df = explorer_df

st.dataframe(
    filtered_df[['identity_id', 'name', 'type', 'department', 'ad_user', 'aws_user', 'okta_login', 'privilege_count']],
    use_container_width=True,
    height=320,
    column_config={
        'identity_id':      st.column_config.TextColumn('Identity ID',  width='small'),
        'name':             st.column_config.TextColumn('Name',         width='medium'),
        'type':             st.column_config.TextColumn('Type',         width='small'),
        'department':       st.column_config.TextColumn('Department',   width='medium'),
        'ad_user':          st.column_config.TextColumn('AD Account',   width='medium'),
        'aws_user':         st.column_config.TextColumn('AWS Account',  width='medium'),
        'okta_login':       st.column_config.TextColumn('Okta Login',   width='medium'),
        'privilege_count':  st.column_config.ProgressColumn('Privileges', min_value=0, max_value=int(explorer_df['privilege_count'].fillna(0).max()), format='%d'),
    }
)

st.divider()

# ── Deep Dive ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Deep Dive</h2></div>', unsafe_allow_html=True)

if filtered_df.empty:
    st.info("No identities match your search. Try a different query.")
else:
    selected_identity = st.selectbox(
        "Select an identity to inspect in detail:",
        filtered_df['identity_id'].tolist(),
        format_func=lambda x: f"{x} — {filtered_df[filtered_df['identity_id']==x]['name'].values[0]}" if not filtered_df[filtered_df['identity_id']==x].empty else x
    )

    if selected_identity:
        identity_data = filtered_df[filtered_df['identity_id'] == selected_identity].iloc[0]

        col_info, col_platforms = st.columns(2)

        with col_info:
            st.markdown("""
            <div class="info-card">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:0.8rem;">IDENTITY PROFILE</div>
            """, unsafe_allow_html=True)
            st.markdown(f"**👤 Name:** {identity_data['name']}")
            st.markdown(f"**🏷️ Type:** `{identity_data['type']}`")
            st.markdown(f"**🏢 Department:** {identity_data['department']}")
            priv_count = identity_data.get('privilege_count', 0) or 0
            st.markdown(f"**🔑 Privilege Count:** `{int(priv_count)}`")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_platforms:
            st.markdown("""
            <div class="info-card">
                <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-bottom:0.8rem;">PLATFORM ACCOUNTS</div>
            """, unsafe_allow_html=True)
            ad_status = identity_data.get('ad_status', 'unknown')
            aws_status = identity_data.get('aws_status', 'unknown')
            okta_status = identity_data.get('okta_status', 'unknown')
            def status_icon(s): return "🟢" if str(s).lower() in ['active', 'enabled'] else "🔴"
            st.markdown(f"**🪟 Active Directory:** `{identity_data.get('ad_user','—')}` {status_icon(ad_status)} `{ad_status}`")
            st.markdown(f"**☁️ AWS IAM:** `{identity_data.get('aws_user','—')}` {status_icon(aws_status)} `{aws_status}`")
            st.markdown(f"**🔐 Okta:** `{identity_data.get('okta_login','—')}` {status_icon(okta_status)} `{okta_status}`")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown('<div class="section-title"><h2>Effective Privileges</h2></div>', unsafe_allow_html=True)
        privs = identity_data.get('effective_privileges', [])
        if isinstance(privs, list) and privs:
            badges_html = " ".join([f'<span class="badge badge-info">{p}</span>' for p in privs])
            st.markdown(f'<div style="display:flex;flex-wrap:wrap;gap:0.4rem;">{badges_html}</div>', unsafe_allow_html=True)
        else:
            st.info("No effective privileges found for this identity.")
