import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from backend.identity_resolver import IdentityResolver
from backend.privilege_analyzer import PrivilegeAnalyzer

DARK_BG  = '#0F172A'
CARD_BG  = '#1E293B'
TEXT_COL = '#94A3B8'
FONT_FAM = 'Inter, sans-serif'
GRID_COL = 'rgba(148,163,184,0.08)'
DARK_LAYOUT = dict(
    paper_bgcolor=DARK_BG, plot_bgcolor=CARD_BG,
    font=dict(family=FONT_FAM, color=TEXT_COL),
    title_font=dict(size=13, color='#F1F5F9', family=FONT_FAM),
)

st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
.exp-page-hdr {
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
.id-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.id-kpi:hover { border-color:rgba(148,163,184,0.2);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.id-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.id-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1; }
.id-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.chart-wrapper {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1rem 0.5rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.chart-wrapper:hover { border-color:rgba(148,163,184,0.18); }
.profile-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.2rem 1.4rem;box-shadow:0 4px 20px rgba(0,0,0,0.3);
    animation:fadeIn 0.35s ease both;transition:all 0.2s ease;
}
.profile-card:hover { border-color:rgba(148,163,184,0.2); }
.platform-row {
    display:flex;align-items:center;gap:0.6rem;padding:0.5rem 0;
    border-bottom:1px solid rgba(148,163,184,0.07);font-size:0.87rem;color:#94A3B8;
}
.platform-row:last-child { border-bottom:none; }
.status-active {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.25);
    border-radius:100px;font-size:0.62rem;font-weight:700;color:#22C55E;
}
.status-inactive {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);
    border-radius:100px;font-size:0.62rem;font-weight:700;color:#EF4444;
}
.status-unknown {
    display:inline-flex;align-items:center;padding:0.1rem 0.5rem;
    background:rgba(100,116,139,0.1);border:1px solid rgba(100,116,139,0.2);
    border-radius:100px;font-size:0.62rem;font-weight:700;color:#64748B;
}
.priv-badge {
    display:inline-flex;align-items:center;padding:0.2rem 0.65rem;
    background:rgba(30,41,59,0.8);border:1px solid rgba(148,163,184,0.1);
    border-radius:6px;font-size:0.72rem;font-weight:600;color:#F1F5F9;
    margin:0.2rem;transition:all 0.15s;
}
.priv-badge:hover { border-color:rgba(59,130,246,0.4);color:#3B82F6; }
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

st.markdown("""
<div class="exp-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#3B82F6;margin-bottom:0.3rem;">Identity Management</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Identity Explorer</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Search, inspect, and analyse identities across Active Directory, AWS IAM, and Okta.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#3B82F6;
                letter-spacing:1px;text-transform:uppercase;">🔍 SEARCH & INVESTIGATE</span>
</div>
""", unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_identities():
    return IdentityResolver().get_resolved_identities()

@st.cache_data(ttl=300)
def load_privileges():
    return PrivilegeAnalyzer().analyze_all_identities()

identities_df = load_identities()
privileges_df = load_privileges()

explorer_df = identities_df.merge(
    privileges_df[['identity_id', 'effective_privileges', 'privilege_count']],
    on='identity_id', how='left'
)

total_ids  = len(explorer_df)
privileged = int(explorer_df['privilege_count'].fillna(0).gt(5).sum())
correlated = int(((explorer_df['ad_user'].notna()) & (explorer_df['aws_user'].notna()) & (explorer_df['okta_login'].notna())).sum())
orphaned   = int(explorer_df[['ad_user', 'aws_user', 'okta_login']].isna().all(axis=1).sum())

# KPI Row
col1, col2, col3, col4 = st.columns(4)
kpi_items = [
    (col1, "Total Identities",    total_ids,  "#3B82F6", "Across all platforms"),
    (col2, "Highly Privileged",   privileged, "#F97316", f"{round(privileged/total_ids*100) if total_ids else 0}% have 5+ privileges"),
    (col3, "Fully Correlated",    correlated, "#22C55E", "AD + AWS + Okta present"),
    (col4, "Potential Orphans",   orphaned,   "#EAB308", "No platform accounts found"),
]
for col, lbl, val, clr, sub in kpi_items:
    with col:
        st.markdown(f"""
        <div class="id-kpi">
            <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                        background:{clr};box-shadow:0 0 10px {clr}44;"></div>
            <div class="id-kpi-lbl">{lbl}</div>
            <div class="id-kpi-val" style="color:{clr};">{val}</div>
            <div class="id-kpi-sub">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

st.divider()
st.markdown('<div class="section-hdr"><h2>Identity Search</h2></div>', unsafe_allow_html=True)

col_search, col_filter = st.columns([3, 1])
with col_search:
    search_query = st.text_input("🔍 Search by Identity ID, Name, or Department",
                                  placeholder="Try 'alice', 'finance', or 'EMP-001' …")
with col_filter:
    type_filter = st.selectbox("Identity Type",
                                ['All'] + sorted(explorer_df['type'].dropna().unique().tolist()))

filtered_df = explorer_df.copy()
if type_filter != 'All':
    filtered_df = filtered_df[filtered_df['type'] == type_filter]
if search_query:
    filtered_df = filtered_df[
        filtered_df['identity_id'].str.contains(search_query, case=False, na=False) |
        filtered_df['name'].str.contains(search_query, case=False, na=False) |
        filtered_df['department'].str.contains(search_query, case=False, na=False)
    ]

st.caption(f'Showing **{len(filtered_df)}** of **{total_ids}** identities')

max_priv = int(explorer_df['privilege_count'].fillna(0).max()) or 1
st.dataframe(
    filtered_df[['identity_id', 'name', 'type', 'department', 'ad_user', 'aws_user', 'okta_login', 'privilege_count']]
        .sort_values('privilege_count', ascending=False),
    width="stretch", height=300,
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

# Charts
st.divider()
st.markdown('<div class="section-hdr"><h2>Population Breakdown</h2></div>', unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)
PALETTE = ['#3B82F6', '#8B5CF6', '#22C55E', '#F97316', '#EAB308', '#06B6D4']

with col_c1:
    st.markdown('<div class="chart-wrapper"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem;">Identities by Department</div>', unsafe_allow_html=True)
    dept_counts = explorer_df['department'].value_counts().reset_index()
    dept_counts.columns = ['Department', 'Count']
    dept_counts = dept_counts.sort_values('Count', ascending=True)
    fig_dept = px.bar(dept_counts, x='Count', y='Department', orientation='h',
                      color='Count',
                      color_continuous_scale=[[0, '#1E3A5F'], [1.0, '#3B82F6']],
                      text='Count')
    fig_dept.update_layout(**DARK_LAYOUT, height=280, showlegend=False,
        coloraxis_showscale=False,
        xaxis=dict(gridcolor=GRID_COL, tickfont=dict(size=10, color=TEXT_COL)),
        yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=10, color='#F1F5F9')),
        margin=dict(t=10, b=10, l=10, r=40), bargap=0.3)
    fig_dept.update_traces(textposition='outside',
        textfont=dict(color='#F1F5F9', size=11, weight=600),
        marker_line_color='rgba(0,0,0,0)',
        hovertemplate='<b>%{y}</b><br>%{x} identities<extra></extra>')
    st.plotly_chart(fig_dept, width="stretch")
    st.markdown('</div>', unsafe_allow_html=True)

with col_c2:
    st.markdown('<div class="chart-wrapper"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.1rem;">Identity Type Distribution</div>', unsafe_allow_html=True)
    type_counts = explorer_df['type'].value_counts().reset_index()
    type_counts.columns = ['Type', 'Count']
    fig_types = px.pie(type_counts, values='Count', names='Type', hole=0.55,
                       color_discrete_sequence=PALETTE)
    fig_types.update_layout(**DARK_LAYOUT, height=280,
        legend=dict(font=dict(color=TEXT_COL, size=10), bgcolor='rgba(0,0,0,0)',
                    orientation='h', yanchor='bottom', y=-0.15, xanchor='center', x=0.5),
        margin=dict(t=10, b=30, l=10, r=10),
        annotations=[dict(text=f'<b style="color:#F1F5F9">{total_ids}</b>', x=0.5, y=0.5,
                          font_size=22, showarrow=False, font_color='#F1F5F9')])
    fig_types.update_traces(textinfo='percent', textfont=dict(size=11, color='white'),
        hovertemplate='<b>%{label}</b><br>%{value} (%{percent})<extra></extra>',
        marker=dict(line=dict(color=DARK_BG, width=2)))
    st.plotly_chart(fig_types, width="stretch")
    st.markdown('</div>', unsafe_allow_html=True)

# Privilege distribution
st.markdown('<div class="section-hdr"><h2>Privilege Distribution</h2></div>', unsafe_allow_html=True)
st.markdown('<div class="chart-wrapper">', unsafe_allow_html=True)
priv_df = explorer_df[['privilege_count']].fillna(0)
fig_priv = px.histogram(priv_df, x='privilege_count', nbins=25,
    color_discrete_sequence=['#3B82F6'],
    labels={'privilege_count': 'Number of Privileges', 'count': 'Identities'})
fig_priv.update_layout(**DARK_LAYOUT,
    xaxis=dict(gridcolor=GRID_COL, title='Privilege Count', tickfont=dict(size=11, color=TEXT_COL)),
    yaxis=dict(gridcolor=GRID_COL, title='Number of Identities', tickfont=dict(size=11, color=TEXT_COL)),
    margin=dict(t=10, b=20, l=10, r=10), bargap=0.04, height=240)
fig_priv.update_traces(marker_opacity=0.85,
    marker_line_color='rgba(255,255,255,0.15)', marker_line_width=0.5,
    hovertemplate='%{x} privileges: <b>%{y} identities</b><extra></extra>')
fig_priv.add_vline(x=5, line_dash="dot", line_color="rgba(249,115,22,0.5)", line_width=1.5,
                   annotation_text="High privilege threshold",
                   annotation_position="top right",
                   annotation_font=dict(size=10, color='#F97316'))
st.plotly_chart(fig_priv, width="stretch")
st.markdown('</div>', unsafe_allow_html=True)

# ── Identity Deep Dive ─────────────────────────────────────────────────────────
st.divider()
st.markdown('<div class="section-hdr"><h2>Identity Deep Dive</h2></div>', unsafe_allow_html=True)

if filtered_df.empty:
    st.info("No identities match your search. Try a different query.")
else:
    selected_identity = st.selectbox(
        "Select an identity to inspect:",
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
        priv_color = '#EF4444' if priv_count > 10 else '#F97316' if priv_count > 5 else '#22C55E'

        def status_badge(s):
            sl = str(s).lower()
            if sl in ['active', 'enabled']:
                return '<span class="status-active">● Active</span>'
            elif sl in ['inactive', 'disabled', 'suspended']:
                return '<span class="status-inactive">● Inactive</span>'
            else:
                return f'<span class="status-unknown">{s}</span>'

        col_info, col_gauge, col_platforms = st.columns([1.5, 1, 1.5])

        with col_info:
            initials = "".join([n[0].upper() for n in str(identity_data['name']).split()[:2]])
            dept_str = str(identity_data.get('department', '—'))
            type_str = str(identity_data.get('type', '—'))
            st.markdown(f"""
            <div class="profile-card">
                <div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:1rem;">
                    <div style="width:44px;height:44px;border-radius:50%;flex-shrink:0;
                                background:linear-gradient(135deg,#3B82F6,#1D4ED8);
                                display:flex;align-items:center;justify-content:center;
                                font-size:1rem;font-weight:800;color:white;
                                box-shadow:0 0 16px rgba(59,130,246,0.3);">{initials}</div>
                    <div>
                        <div style="font-size:1.1rem;font-weight:800;color:#F1F5F9;">{identity_data['name']}</div>
                        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.2rem;">
                            <span style="background:rgba(59,130,246,0.1);color:#3B82F6;
                                         border:1px solid rgba(59,130,246,0.25);
                                         padding:1px 8px;border-radius:100px;font-size:0.65rem;font-weight:700;">{type_str}</span>
                            <span style="background:rgba(100,116,139,0.1);color:#94A3B8;
                                         border:1px solid rgba(100,116,139,0.2);
                                         padding:1px 8px;border-radius:100px;font-size:0.65rem;font-weight:600;">{dept_str}</span>
                        </div>
                    </div>
                </div>
                <div style="font-size:0.82rem;color:#94A3B8;line-height:1.8;">
                    <div><strong style="color:#F1F5F9;">ID:</strong> <code>{identity_data['identity_id']}</code></div>
                    <div><strong style="color:#F1F5F9;">Privileges:</strong> {priv_count}
                        <span style="color:{priv_color};font-size:0.72rem;font-weight:700;margin-left:0.4rem;">({priv_label})</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_gauge:
            # Circular risk gauge (privilege-based)
            pct = min(priv_count / 20 * 100, 100)
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=priv_count,
                number=dict(font=dict(size=22, color=priv_color, family=FONT_FAM), suffix=" privs"),
                gauge={
                    'axis': {'range': [0, 20], 'tickcolor': '#475569', 'tickwidth': 1,
                             'tickfont': dict(size=9, color=TEXT_COL)},
                    'bar': {'color': priv_color, 'thickness': 0.22},
                    'bgcolor': CARD_BG, 'borderwidth': 0,
                    'steps': [
                        {'range': [0, 5],   'color': 'rgba(34,197,94,0.08)'},
                        {'range': [5, 10],  'color': 'rgba(249,115,22,0.08)'},
                        {'range': [10, 20], 'color': 'rgba(239,68,68,0.08)'},
                    ],
                    'threshold': {'line': {'color': priv_color, 'width': 3}, 'thickness': 0.85, 'value': priv_count}
                },
                title=dict(text="Privilege Level", font=dict(size=12, color='#F1F5F9', family=FONT_FAM))
            ))
            fig_g.update_layout(paper_bgcolor=DARK_BG, font=dict(family=FONT_FAM),
                height=220, margin=dict(t=60, b=10, l=20, r=20))
            st.plotly_chart(fig_g, width="stretch")

        with col_platforms:
            ad_status   = identity_data.get('ad_status', 'unknown')
            aws_status  = identity_data.get('aws_status', 'unknown')
            okta_status = identity_data.get('okta_status', 'unknown')
            st.markdown(f"""
            <div class="profile-card">
                <div style="font-size:0.62rem;text-transform:uppercase;letter-spacing:1px;
                            color:#64748B;margin-bottom:0.9rem;font-weight:700;">PLATFORM ACCOUNTS</div>
                <div class="platform-row">
                    <span style="font-size:0.9rem;">🏢</span>
                    <span style="font-weight:600;min-width:110px;color:#F1F5F9;">Active Directory</span>
                    <code style="font-size:0.75rem;color:#94A3B8;">{identity_data.get('ad_user','—')}</code>
                    {status_badge(ad_status)}
                </div>
                <div class="platform-row">
                    <span style="font-size:0.9rem;">☁️</span>
                    <span style="font-weight:600;min-width:110px;color:#F1F5F9;">AWS IAM</span>
                    <code style="font-size:0.75rem;color:#94A3B8;">{identity_data.get('aws_user','—')}</code>
                    {status_badge(aws_status)}
                </div>
                <div class="platform-row">
                    <span style="font-size:0.9rem;">🔐</span>
                    <span style="font-weight:600;min-width:110px;color:#F1F5F9;">Okta</span>
                    <code style="font-size:0.75rem;color:#94A3B8;">{identity_data.get('okta_login','—')}</code>
                    {status_badge(okta_status)}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('<div class="section-hdr" style="margin-top:1rem;"><h2>Effective Privileges</h2></div>', unsafe_allow_html=True)
        privs = identity_data.get('effective_privileges', [])
        if isinstance(privs, list) and privs:
            PRIV_COLORS = ['#3B82F6', '#8B5CF6', '#22C55E', '#F97316', '#EAB308', '#06B6D4']
            badges_html = " ".join([
                f'<span class="priv-badge" style="border-left:2px solid {PRIV_COLORS[i % len(PRIV_COLORS)]};">{p}</span>'
                for i, p in enumerate(privs)
            ])
            st.markdown(f'<div style="display:flex;flex-wrap:wrap;gap:0.2rem;padding:0.2rem 0;">{badges_html}</div>', unsafe_allow_html=True)
        else:
            st.info("This identity has no effective privileges on record.")

st.markdown('</div>', unsafe_allow_html=True)
