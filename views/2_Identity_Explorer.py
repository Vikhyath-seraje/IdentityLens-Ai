import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
from backend.identity_resolver import IdentityResolver
from backend.privilege_analyzer import PrivilegeAnalyzer

# ── Page header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Identity Management</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Identity Explorer</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Search, inspect, and analyse identities across Active Directory, AWS IAM, and Okta.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(0,96,168,0.06);border:1px solid rgba(0,96,168,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#0060A8;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">SEARCH &amp; INVESTIGATE</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(14px)}
    to{opacity:1;transform:translateY(0)}
}
.chart-wrapper {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem 1rem 0.5rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    transition:box-shadow 0.25s;animation:fadeSlideUp 0.4s ease both;
}
.chart-wrapper:hover { box-shadow:0 6px 20px rgba(0,0,0,0.1); }
.section-title h2 {
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}
.kpi-insight { font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4; }
.identity-profile-card {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1.2rem 1.4rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    animation:fadeSlideUp 0.35s ease both;transition:box-shadow 0.2s;
}
.identity-profile-card:hover { box-shadow:0 4px 16px rgba(0,0,0,0.1); }
.platform-row {
    display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0;
    border-bottom:1px solid #F4F5F6;font-size:0.87rem;color:#1A1A1A;
}
.platform-row:last-child { border-bottom:none; }
.status-badge-active {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(22,163,74,0.08);border:1px solid rgba(22,163,74,0.2);
    border-radius:100px;font-size:0.65rem;font-weight:700;color:#16A34A;
}
.status-badge-inactive {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(220,38,38,0.08);border:1px solid rgba(220,38,38,0.2);
    border-radius:100px;font-size:0.65rem;font-weight:700;color:#DC2626;
}
.status-badge-unknown {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(107,114,128,0.08);border:1px solid rgba(107,114,128,0.2);
    border-radius:100px;font-size:0.65rem;font-weight:700;color:#6B7280;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_identities():
    resolver = IdentityResolver()
    return resolver.get_resolved_identities()

@st.cache_data(ttl=300)
def load_privileges():
    analyzer = PrivilegeAnalyzer()
    return analyzer.analyze_all_identities()

identities_df = load_identities()
privileges_df = load_privileges()

explorer_df = identities_df.merge(
    privileges_df[['identity_id', 'effective_privileges', 'privilege_count']],
    on='identity_id', how='left'
)

total_ids   = len(explorer_df)
privileged  = int(explorer_df['privilege_count'].fillna(0).gt(5).sum())
correlated  = int(((explorer_df['ad_user'].notna()) & (explorer_df['aws_user'].notna()) & (explorer_df['okta_login'].notna())).sum())

# ── KPI Row ─────────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Identities", total_ids)
    st.markdown('<div class="kpi-insight">Across all platforms</div>', unsafe_allow_html=True)
with col2:
    st.metric("Highly Privileged", privileged)
    st.markdown(f'<div class="kpi-insight">{round(privileged/total_ids*100)}% have 5+ privileges</div>', unsafe_allow_html=True)
with col3:
    st.metric("Fully Correlated", correlated)
    st.markdown('<div class="kpi-insight">AD + AWS + Okta all present</div>', unsafe_allow_html=True)
with col4:
    orphaned = int(explorer_df[['ad_user', 'aws_user', 'okta_login']].isna().all(axis=1).sum())
    st.metric("Potential Orphans", orphaned)
    st.markdown('<div class="kpi-insight">No platform accounts found</div>', unsafe_allow_html=True)

st.divider()

# ── Search & Table ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Search</h2></div>', unsafe_allow_html=True)

col_search, col_filter = st.columns([3, 1])
with col_search:
    search_query = st.text_input(
        " Search by Identity ID, Name, or Department",
        placeholder="Try 'alice', 'finance', or 'EMP-001' …"
    )
with col_filter:
    type_filter = st.selectbox(
        "Identity Type",
        ['All'] + sorted(explorer_df['type'].dropna().unique().tolist())
    )

filtered_df = explorer_df.copy()
if type_filter != 'All':
    filtered_df = filtered_df[filtered_df['type'] == type_filter]
if search_query:
    filtered_df = filtered_df[
        filtered_df['identity_id'].str.contains(search_query, case=False, na=False) |
        filtered_df['name'].str.contains(search_query, case=False, na=False) |
        filtered_df['department'].str.contains(search_query, case=False, na=False)
    ]
    st.caption(f'Showing **{len(filtered_df)}** result(s) for "{search_query}"')
else:
    st.caption(f'Showing all **{len(filtered_df)}** identities — click any row to explore')

max_priv = int(explorer_df['privilege_count'].fillna(0).max()) or 1
st.dataframe(
    filtered_df[['identity_id', 'name', 'type', 'department', 'ad_user', 'aws_user', 'okta_login', 'privilege_count']],
    use_container_width=True,
    height=320,
    column_config={
        'identity_id':     st.column_config.TextColumn('Identity ID',  width='small'),
        'name':            st.column_config.TextColumn('Name',         width='medium'),
        'type':            st.column_config.TextColumn('Type',         width='small'),
        'department':      st.column_config.TextColumn('Department',   width='medium'),
        'ad_user':         st.column_config.TextColumn('AD Account',   width='medium'),
        'aws_user':        st.column_config.TextColumn('AWS Account',  width='medium'),
        'okta_login':      st.column_config.TextColumn('Okta Login',   width='medium'),
        'privilege_count': st.column_config.ProgressColumn('Privileges', min_value=0, max_value=max_priv, format='%d'),
    }
)

st.divider()

# ── Identity Charts ──────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Population Breakdown</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)

with col_c1:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    dept_counts = explorer_df['department'].value_counts().reset_index()
    dept_counts.columns = ['Department', 'Count']
    dept_counts = dept_counts.sort_values('Count', ascending=True)

    fig_dept = px.bar(
        dept_counts, x='Count', y='Department', orientation='h',
        color='Count',
        color_continuous_scale=[[0, '#FECACA'], [1.0, '#E60028']],
        text='Count',
        title="How many people are in each department?"
    )
    fig_dept.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=13, color='#4A4A4A'),
        height=280, showlegend=False, coloraxis_showscale=False,
        xaxis=dict(gridcolor='rgba(0,0,0,0.06)', tickfont=dict(size=11)),
        yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=11, color='#4A4A4A')),
        margin=dict(t=50, b=10, l=10, r=40),
        bargap=0.3,
    )
    fig_dept.update_traces(
        textposition='outside', textfont=dict(color='#1A1A1A', size=11, weight=600),
        marker_line_color='rgba(0,0,0,0)',
        hovertemplate='<b>%{y}</b><br>%{x} identities<extra></extra>',
    )
    st.plotly_chart(fig_dept, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
    type_counts = explorer_df['type'].value_counts().reset_index()
    type_counts.columns = ['Type', 'Count']

    PALETTE = ['#E60028', '#1a56db', '#10b981', '#f59e0b', '#8b5cf6']
    fig_types = px.pie(
        type_counts, values='Count', names='Type', hole=0.55,
        color_discrete_sequence=PALETTE,
        title="What types of identities exist?"
    )
    fig_types.update_layout(
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        font=dict(family='Inter, sans-serif', color='#1A1A1A'),
        title_font=dict(size=13, color='#4A4A4A'),
        height=280,
        legend=dict(font=dict(color='#4A4A4A', size=11), bgcolor='rgba(0,0,0,0)',
                    orientation='h', yanchor='bottom', y=-0.15, xanchor='center', x=0.5),
        margin=dict(t=50, b=30, l=10, r=10),
        annotations=[dict(text=f'<b>{total_ids}</b>', x=0.5, y=0.5,
                          font_size=22, showarrow=False, font_color='#1A1A1A')]
    )
    fig_types.update_traces(
        textinfo='percent', textfont=dict(size=12, color='white'),
        hovertemplate='<b>%{label}</b><br>%{value} identities (%{percent})<extra></extra>',
        marker=dict(line=dict(color='white', width=2)),
        pull=[0.04 if i == 0 else 0 for i in range(len(type_counts))]
    )
    st.plotly_chart(fig_types, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ── Privilege Distribution ───────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Privilege Distribution</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)

priv_df = explorer_df[['privilege_count']].fillna(0)
fig_priv = px.histogram(
    priv_df, x='privilege_count', nbins=25,
    color_discrete_sequence=['#1a56db'],
    title="How many privileges do identities typically hold? Outliers on the right deserve scrutiny.",
    labels={'privilege_count': 'Number of Privileges', 'count': 'Identities'}
)
fig_priv.update_layout(
    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
    font=dict(family='Inter, sans-serif', color='#1A1A1A'),
    title_font=dict(size=13, color='#4A4A4A'),
    xaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Privilege Count', tickfont=dict(size=11)),
    yaxis=dict(gridcolor='rgba(0,0,0,0.06)', title='Number of Identities', tickfont=dict(size=11)),
    margin=dict(t=55, b=20, l=10, r=10),
    bargap=0.04,
    height=250,
)
fig_priv.update_traces(
    marker_opacity=0.8,
    marker_line_color='rgba(255,255,255,0.5)', marker_line_width=0.5,
    hovertemplate='%{x} privileges: <b>%{y} identities</b><extra></extra>'
)
# Add a vertical line at 5 (the "highly privileged" threshold)
fig_priv.add_vline(x=5, line_dash="dot", line_color="rgba(220,38,38,0.5)", line_width=1.5,
                   annotation_text="Highly privileged threshold",
                   annotation_position="top right",
                   annotation_font=dict(size=10, color='#DC2626'))
st.plotly_chart(fig_priv, use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# ── Deep Dive ────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Identity Deep Dive</h2></div>', unsafe_allow_html=True)

if filtered_df.empty:
    st.info("No identities match your search. Try a different query.")
else:
    selected_identity = st.selectbox(
        "Pick an identity to inspect in detail:",
        filtered_df['identity_id'].tolist(),
        format_func=lambda x: (
            f"{x} — {filtered_df[filtered_df['identity_id']==x]['name'].values[0]}"
            if not filtered_df[filtered_df['identity_id']==x].empty else x
        )
    )

    if selected_identity:
        identity_data = filtered_df[filtered_df['identity_id'] == selected_identity].iloc[0]
        priv_count = int(identity_data.get('privilege_count', 0) or 0)
        priv_label = "High" if priv_count > 10 else "Medium" if priv_count > 5 else "Low"
        priv_color = '#DC2626' if priv_count > 10 else '#D97706' if priv_count > 5 else '#16A34A'

        col_info, col_platforms = st.columns(2)

        def status_badge(s):
            sl = str(s).lower()
            if sl in ['active', 'enabled']:
                return '<span class="status-badge-active">Active</span>'
            elif sl in ['inactive', 'disabled', 'suspended']:
                return '<span class="status-badge-inactive">Inactive</span>'
            else:
                return f'<span class="status-badge-unknown">{s}</span>'

        with col_info:
            st.markdown(f"""
            <div class="identity-profile-card">
                <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                            color:#6B6B6B;margin-bottom:0.9rem;font-weight:700;">IDENTITY PROFILE</div>
                <div style="font-size:1.2rem;font-weight:800;color:#1A1A1A;margin-bottom:0.3rem;">
                    {identity_data['name']}
                </div>
                <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem;">
                    <span style="background:rgba(0,96,168,0.08);color:#0060A8;border:1px solid rgba(0,96,168,0.2);
                                 padding:0.15rem 0.6rem;border-radius:100px;font-size:0.7rem;font-weight:700;">
                        {identity_data['type']}
                    </span>
                    <span style="background:rgba(107,114,128,0.08);color:#4A4A4A;border:1px solid rgba(107,114,128,0.2);
                                 padding:0.15rem 0.6rem;border-radius:100px;font-size:0.7rem;font-weight:600;">
                        {identity_data['department']}
                    </span>
                </div>
                <div style="font-size:0.83rem;color:#4A4A4A;line-height:1.8;">
                    <div><strong>ID:</strong> <code>{identity_data['identity_id']}</code></div>
                    <div><strong>Privileges:</strong> {priv_count}
                        <span style="color:{priv_color};font-size:0.75rem;font-weight:700;margin-left:0.4rem;">
                            ({priv_label} privilege level)
                        </span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_platforms:
            ad_status   = identity_data.get('ad_status', 'unknown')
            aws_status  = identity_data.get('aws_status', 'unknown')
            okta_status = identity_data.get('okta_status', 'unknown')
            st.markdown(f"""
            <div class="identity-profile-card">
                <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                            color:#6B6B6B;margin-bottom:0.9rem;font-weight:700;">PLATFORM ACCOUNTS</div>
                <div class="platform-row">
                    <span style="font-size:1rem;"></span>
                    <span style="font-weight:600;min-width:130px;">Active Directory</span>
                    <code style="font-size:0.78rem;color:#4A4A4A;">{identity_data.get('ad_user','—')}</code>
                    {status_badge(ad_status)}
                </div>
                <div class="platform-row">
                    <span style="font-size:1rem;"></span>
                    <span style="font-weight:600;min-width:130px;">AWS IAM</span>
                    <code style="font-size:0.78rem;color:#4A4A4A;">{identity_data.get('aws_user','—')}</code>
                    {status_badge(aws_status)}
                </div>
                <div class="platform-row">
                    <span style="font-size:1rem;"></span>
                    <span style="font-weight:600;min-width:130px;">Okta</span>
                    <code style="font-size:0.78rem;color:#4A4A4A;">{identity_data.get('okta_login','—')}</code>
                    {status_badge(okta_status)}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-title"><h2>Effective Privileges</h2></div>', unsafe_allow_html=True)
        privs = identity_data.get('effective_privileges', [])
        if isinstance(privs, list) and privs:
            color_cycle = ['#E60028', '#1a56db', '#16A34A', '#D97706', '#6D28D9', '#0060A8']
            badges_html = " ".join([
                f'<span style="display:inline-flex;align-items:center;padding:0.2rem 0.65rem;'
                f'background:rgba(0,0,0,0.04);border:1px solid #E0E0E0;border-left:3px solid {color_cycle[i % len(color_cycle)]};'
                f'border-radius:4px;font-size:0.75rem;font-weight:600;color:#1A1A1A;margin:0.2rem;">{p}</span>'
                for i, p in enumerate(privs)
            ])
            st.markdown(f'<div style="display:flex;flex-wrap:wrap;gap:0.3rem;padding:0.2rem 0;">{badges_html}</div>', unsafe_allow_html=True)
        else:
            st.info("This identity has no effective privileges on record.")
