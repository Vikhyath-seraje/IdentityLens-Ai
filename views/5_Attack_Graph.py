import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import networkx as nx
import plotly.graph_objects as go
from backend.attack_graph import AttackGraphGenerator
from backend.risk_engine import RiskEngine

# ── Dark theme constants ───────────────────────────────────────────────────────
DARK_BG   = '#0F172A'
CARD_BG   = '#1E293B'
TEXT_COL  = '#94A3B8'
FONT_FAM  = 'Inter, sans-serif'

# Node colors per spec — Identity colors vary by type
NODE_COLORS = {
    'Identity': '#3B82F6',   # Blue (default, overridden below for SA types)
    'Group':    '#8B5CF6',   # Purple
    'Role':     '#F97316',   # Orange
    'Policy':   '#EF4444',   # Red
    'Platform': '#22C55E',   # Green (Resource/Platform)
    'Resource': '#EF4444',   # Red (high-sensitivity resources)
}

# Identity sub-type colors for ITDR differentiation
IDENTITY_TYPE_COLORS = {
    'ServiceAccount':           '#F97316',  # Orange
    'PrivilegedServiceAccount': '#EF4444',  # Red
    'Employee':                 '#3B82F6',  # Blue
    'Contractor':               '#8B5CF6',  # Purple
}

st.markdown("""
<style>
@keyframes fadeIn { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
.graph-page-hdr {
    display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
    padding-bottom:1.2rem;border-bottom:1px solid rgba(148,163,184,0.1);margin-bottom:1.5rem;
}
.graph-section-hdr {
    display:flex;align-items:center;gap:0.75rem;margin:1.75rem 0 1rem;
}
.graph-section-hdr h2 {
    font-size:0.82rem !important;font-weight:700 !important;color:#F1F5F9 !important;
    margin:0 !important;text-transform:uppercase;letter-spacing:0.8px;
}
.graph-section-hdr::after { content:'';flex:1;height:1px;background:rgba(148,163,184,0.1); }
.graph-kpi {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1.1rem 1.2rem;position:relative;overflow:hidden;
    transition:all 0.25s ease;animation:fadeIn 0.4s ease both;
}
.graph-kpi:hover { border-color:rgba(148,163,184,0.2);transform:translateY(-2px);box-shadow:0 8px 32px rgba(0,0,0,0.4); }
.graph-kpi-lbl { font-size:0.6rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:#64748B;margin-bottom:0.4rem; }
.graph-kpi-val { font-size:1.9rem;font-weight:900;letter-spacing:-1px;line-height:1; }
.graph-kpi-sub { font-size:0.65rem;color:#64748B;margin-top:0.4rem; }
.graph-card {
    background:rgba(30,41,59,0.8);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem;box-shadow:0 4px 20px rgba(0,0,0,0.4);
    animation:fadeIn 0.4s ease both;transition:all 0.25s ease;
}
.graph-card:hover { border-color:rgba(148,163,184,0.18); }
.legend-panel {
    background:rgba(15,23,42,0.9);backdrop-filter:blur(20px);
    border:1px solid rgba(148,163,184,0.1);border-radius:12px;
    padding:1rem 1.2rem;margin-top:0.75rem;
}
.legend-row {
    display:flex;align-items:center;gap:0.6rem;
    padding:0.35rem 0;font-size:0.82rem;color:#94A3B8;
    border-bottom:1px solid rgba(148,163,184,0.06);
}
.legend-row:last-child { border-bottom:none; }
.legend-dot { width:12px;height:12px;border-radius:50%;flex-shrink:0; }
.attack-path-banner {
    background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);
    border-left:3px solid #EF4444;border-radius:0 8px 8px 0;
    padding:0.7rem 1rem;font-size:0.82rem;color:#94A3B8;line-height:1.5;margin:0.75rem 0;
}
.info-banner {
    background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.15);
    border-left:3px solid #3B82F6;border-radius:0 8px 8px 0;
    padding:0.7rem 1rem;font-size:0.82rem;color:#94A3B8;line-height:1.5;margin:0.75rem 0;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:1.5rem 2rem 0;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

# ── Page header ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="graph-page-hdr">
    <div>
        <div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
                    color:#3B82F6;margin-bottom:0.3rem;">Threat Intelligence</div>
        <h1 style="font-size:1.5rem;font-weight:800;color:#F1F5F9;margin:0 0 0.25rem;letter-spacing:-0.5px;">
            Attack Graph</h1>
        <p style="font-size:0.85rem;color:#64748B;margin:0;">
            Interactive identity attack path visualization — trace lateral movement across the enterprise.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;gap:0.4rem;
                padding:0.3rem 0.9rem;
                background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.25);
                border-radius:100px;font-size:0.65rem;font-weight:700;color:#8B5CF6;
                letter-spacing:1px;text-transform:uppercase;">🕸️ GRAPH ANALYSIS</span>
</div>
""", unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_graph():
    return AttackGraphGenerator().generate_graph()

@st.cache_data(ttl=300)
def get_high_risk_ids():
    risk_df = RiskEngine().calculate_risk_scores()
    return risk_df[risk_df['risk_level'].isin(['Critical', 'High'])]['identity_id'].tolist()

@st.cache_data(ttl=300)
def load_quarantine_impact():
    """Top-10 quarantined identities with before/after risk — cached so the
    Before/After comparison section does not hit the DB on every rerun."""
    import sqlite3
    import pandas as pd
    try:
        conn = sqlite3.connect('database/identitylens.db')
        qrecs = pd.read_sql_query("""
            SELECT identity_id, pre_risk_score, post_risk_score, pre_risk_level, post_risk_level,
                   tokens_revoked, privileges_removed
            FROM quarantine_records WHERE status='quarantined'
            ORDER BY pre_risk_score DESC LIMIT 10
        """, conn)
        conn.close()
    except Exception:
        qrecs = pd.DataFrame()
    return qrecs

G            = load_graph()
high_risk_ids = get_high_risk_ids()
identity_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'Identity']

# ── KPI Row ────────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
kpi_data = [
    (col1, "Total Nodes",       G.number_of_nodes(), "#3B82F6",  "Entities in the graph"),
    (col2, "Total Edges",       G.number_of_edges(), "#8B5CF6",  "Access relationships"),
    (col3, "Identity Nodes",    len(identity_nodes), "#22C55E",  "Traceable identities"),
    (col4, "High/Critical IDs", len(high_risk_ids),  "#EF4444",  "Require path tracing"),
]
for col, lbl, val, clr, sub in kpi_data:
    with col:
        st.markdown(f"""
        <div class="graph-kpi">
            <div style="position:absolute;left:0;top:0;bottom:0;width:3px;border-radius:3px 0 0 3px;
                        background:{clr};box-shadow:0 0 10px {clr}44;"></div>
            <div class="graph-kpi-lbl">{lbl}</div>
            <div class="graph-kpi-val" style="color:{clr};">{val}</div>
            <div class="graph-kpi-sub">{sub}</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("""
<div class="info-banner">
    <strong style="color:#3B82F6;">How to use:</strong> Select an identity below to trace its full access path —
    from user account → group memberships → role assignments → platform access.
    This reveals potential privilege escalation routes an attacker could exploit.
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="graph-section-hdr"><h2>Graph Controls</h2></div>', unsafe_allow_html=True)

col_sel, col_layout, col_size, col_highlight = st.columns([3, 1, 1, 1])
with col_sel:
    selected_identity = st.selectbox(
        "Trace attack path for identity:",
        ['High/Critical Risk Only', 'All (Full Graph)'] + identity_nodes,
        help="Select an identity to trace their full access path."
    )
with col_layout:
    layout_algo = st.selectbox("Layout", ["spring", "kamada_kawai", "circular"],
                               help="Graph layout algorithm")
with col_size:
    node_scale = st.slider("Node size", min_value=8, max_value=30, value=16, step=2)
with col_highlight:
    highlight_paths = st.checkbox("Highlight Attack Paths", value=True)

# ── Build subgraph ─────────────────────────────────────────────────────────────
if selected_identity == 'High/Critical Risk Only':
    nodes_to_keep = set(high_risk_ids)
    for qid in high_risk_ids:
        if qid in G:
            try:
                nodes_to_keep.update(nx.descendants(G, qid))
            except Exception:
                pass
    subG = G.subgraph(nodes_to_keep)
elif selected_identity == 'All (Full Graph)':
    subG = G
else:
    nodes_to_keep = {selected_identity}
    if selected_identity in G:
        try:
            nodes_to_keep.update(nx.descendants(G, selected_identity))
        except Exception:
            pass
    subG = G.subgraph(nodes_to_keep)

if subG.number_of_nodes() > 600:
    st.warning("The full graph is very large. Please select a specific identity or 'High/Critical Risk Only' for focused path tracing.")
else:
    n_nodes = subG.number_of_nodes()
    n_edges = subG.number_of_edges()
    st.markdown(
        f'<div style="font-size:0.78rem;color:#64748B;margin-bottom:0.5rem;">'
        f'Rendering graph with <strong style="color:#F1F5F9">{n_nodes} nodes</strong> '
        f'and <strong style="color:#F1F5F9">{n_edges} edges</strong></div>',
        unsafe_allow_html=True
    )

    # Layout
    seed = 42
    try:
        if layout_algo == "spring":
            pos = nx.spring_layout(subG, seed=seed, k=2.5)
        elif layout_algo == "kamada_kawai":
            pos = nx.kamada_kawai_layout(subG)
        else:
            pos = nx.circular_layout(subG)
    except Exception:
        pos = nx.spring_layout(subG, seed=seed)

    size_map = {
        'Identity': int(node_scale * 1.35),
        'Group':    int(node_scale * 0.9),
        'Role':     int(node_scale * 0.9),
        'Policy':   int(node_scale * 0.85),
        'Platform': int(node_scale * 1.15),
        'Resource': int(node_scale * 1.0),
    }
    symbol_map = {
        'Identity': 'circle',
        'Group':    'diamond',
        'Role':     'square',
        'Policy':   'triangle-up',
        'Platform': 'star',
        'Resource': 'hexagon',
    }

    fig = go.Figure()

    # Identify attack path nodes (high risk identity path)
    attack_path_nodes = set()
    if highlight_paths and selected_identity not in ['High/Critical Risk Only', 'All (Full Graph)']:
        if selected_identity in G:
            try:
                attack_path_nodes.update(nx.descendants(G, selected_identity))
                attack_path_nodes.add(selected_identity)
            except Exception:
                pass
    elif highlight_paths:
        for qid in high_risk_ids:
            if qid in G:
                try:
                    attack_path_nodes.update(nx.descendants(G, qid))
                    attack_path_nodes.add(qid)
                except Exception:
                    pass

    # Edges — highlight attack paths
    edge_x_normal, edge_y_normal = [], []
    edge_x_attack, edge_y_attack = [], []
    for edge in subG.edges():
        if edge[0] in pos and edge[1] in pos:
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            is_attack = (edge[0] in attack_path_nodes and edge[1] in attack_path_nodes)
            if is_attack and highlight_paths:
                edge_x_attack.extend([x0, x1, None])
                edge_y_attack.extend([y0, y1, None])
            else:
                edge_x_normal.extend([x0, x1, None])
                edge_y_normal.extend([y0, y1, None])

    fig.add_trace(go.Scatter(
        x=edge_x_normal, y=edge_y_normal,
        line=dict(width=1, color='rgba(100,116,139,0.2)'),
        hoverinfo='none', mode='lines', showlegend=False, name='_normal_edge'
    ))
    if edge_x_attack:
        fig.add_trace(go.Scatter(
            x=edge_x_attack, y=edge_y_attack,
            line=dict(width=2.5, color='rgba(239,68,68,0.6)'),
            hoverinfo='none', mode='lines', showlegend=True, name='Attack Path'
        ))

    # Nodes per type
    for ntype, clr in NODE_COLORS.items():
        node_x, node_y, node_hover, node_labels, node_sizes, node_colors = [], [], [], [], [], []
        for node in subG.nodes():
            if node not in pos:
                continue
            node_type = subG.nodes[node].get('type', 'Unknown')
            if node_type != ntype and not (ntype == 'Resource' and node_type == 'Platform'):
                continue
            if ntype == 'Resource' and node_type != 'Platform' and node_type != 'Resource':
                continue
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            nlabel = subG.nodes[node].get('label', str(node))
            node_hover.append(f"<b>{ntype}</b><br>{nlabel}")
            node_labels.append(nlabel)
            # Bigger node if in attack path
            base_size = size_map.get(ntype, node_scale)
            node_sizes.append(int(base_size * 1.4) if (node in attack_path_nodes and highlight_paths) else base_size)
            # Per-identity-type color for Identity nodes (ITDR differentiation)
            if ntype == 'Identity':
                id_type = subG.nodes[node].get('identity_type', 'Employee')
                node_colors.append(IDENTITY_TYPE_COLORS.get(id_type, '#3B82F6'))
            else:
                node_colors.append(clr)

        if not node_x:
            continue

        show_text = n_nodes < 40
        is_attack_type = ntype == 'Identity' and highlight_paths

        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text' if show_text else 'markers',
            name=ntype,
            text=node_labels if show_text else [],
            textposition="top center",
            textfont=dict(size=8, color='rgba(241,245,249,0.7)'),
            hoverinfo='text',
            hovertext=node_hover,
            marker=dict(
                color=node_colors,
                size=node_sizes,
                symbol=symbol_map.get(ntype, 'circle'),
                opacity=0.92,
                line=dict(width=2, color=DARK_BG),
            ),
        ))

    fig.update_layout(
        showlegend=True,
        legend=dict(
            orientation='v', yanchor='top', y=1, xanchor='left', x=1.01,
            font=dict(size=11, color='#94A3B8', family=FONT_FAM),
            bgcolor='rgba(15,23,42,0.9)',
            bordercolor='rgba(148,163,184,0.15)', borderwidth=1,
            itemsizing='constant',
        ),
        hovermode='closest',
        paper_bgcolor=DARK_BG,
        plot_bgcolor='rgba(15,23,42,0.5)',
        margin=dict(b=10, l=5, r=150, t=10),
        height=600,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, mirror=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, mirror=False),
    )

    st.markdown('<div class="graph-card">', unsafe_allow_html=True)
    st.plotly_chart(fig, width="stretch", config={'displayModeBar': True, 'scrollZoom': True})
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Legend ────────────────────────────────────────────────────────────────
    col_leg1, col_leg2 = st.columns(2)

    with col_leg1:
        st.markdown("""
        <div class="legend-panel">
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                        color:#64748B;margin-bottom:0.75rem;font-weight:700;">Node Types</div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#3B82F6;box-shadow:0 0 6px rgba(59,130,246,0.5);"></span>
                <strong style="color:#F1F5F9;">Employee</strong>
                <span style="margin-left:auto;font-size:0.75rem;">Regular user identity</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#8B5CF6;box-shadow:0 0 6px rgba(139,92,246,0.5);"></span>
                <strong style="color:#F1F5F9;">Contractor</strong>
                <span style="margin-left:auto;font-size:0.75rem;">External worker</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#F97316;box-shadow:0 0 6px rgba(249,115,22,0.5);"></span>
                <strong style="color:#F1F5F9;">Service Account</strong>
                <span style="margin-left:auto;font-size:0.75rem;">Automated / non-human</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#EF4444;box-shadow:0 0 6px rgba(239,68,68,0.5);"></span>
                <strong style="color:#F1F5F9;">Privileged SA</strong>
                <span style="margin-left:auto;font-size:0.75rem;">Elevated service account</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#8B5CF6;box-shadow:0 0 6px rgba(139,92,246,0.5);transform:rotate(45deg);border-radius:2px;"></span>
                <strong style="color:#F1F5F9;">Group</strong>
                <span style="margin-left:auto;font-size:0.75rem;">AD or Okta group</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#F97316;box-shadow:0 0 6px rgba(249,115,22,0.5);border-radius:2px;"></span>
                <strong style="color:#F1F5F9;">Role</strong>
                <span style="margin-left:auto;font-size:0.75rem;">IAM role / permission set</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#EF4444;box-shadow:0 0 6px rgba(239,68,68,0.5);clip-path:polygon(50% 0%,100% 100%,0% 100%);border-radius:0;"></span>
                <strong style="color:#F1F5F9;">Resource</strong>
                <span style="margin-left:auto;font-size:0.75rem;">High-sensitivity target</span>
            </div>
            <div class="legend-row">
                <span class="legend-dot" style="background:#22C55E;box-shadow:0 0 6px rgba(34,197,94,0.5);"></span>
                <strong style="color:#F1F5F9;">Platform</strong>
                <span style="margin-left:auto;font-size:0.75rem;">AWS, AD, or Okta</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col_leg2:
        st.markdown("""
        <div class="legend-panel">
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                        color:#64748B;margin-bottom:0.75rem;font-weight:700;">Reading the Graph</div>
            <div style="font-size:0.82rem;color:#94A3B8;line-height:1.7;">
                Edges represent <strong style="color:#F1F5F9;">access relationships</strong>.
                Follow the path:<br>
                <code style="font-size:0.75rem;">Identity → Group → Role → Platform/Resource</code><br><br>
                <span style="color:#EF4444;font-weight:600;">Red highlighted edges</span> indicate
                attack paths from high-risk identities — these represent the most dangerous
                privilege escalation routes.<br><br>
                Use <strong style="color:#F1F5F9;">scroll to zoom</strong> and
                <strong style="color:#F1F5F9;">drag to pan</strong> the graph.
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Before vs After Quarantine Comparison ─────────────────────────────────────
st.markdown('<div class="graph-section-hdr"><h2>Before vs After Quarantine — Impact Visualization</h2></div>', unsafe_allow_html=True)

qrecs = load_quarantine_impact()

if qrecs.empty:
    st.markdown("""
    <div class="info-banner">
        No quarantine records found. Go to the <strong style="color:#3B82F6;">Quarantine Center</strong>
        to quarantine high-risk identities and see the before/after impact visualization here.
    </div>
    """, unsafe_allow_html=True)
else:
    col_before, col_after = st.columns(2)

    with col_before:
        st.markdown('<div class="graph-card"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#EF4444;margin-bottom:0.5rem;">BEFORE QUARANTINE</div>', unsafe_allow_html=True)
        fig_before = go.Figure()
        names = qrecs['identity_id'].str[:12].tolist()
        pre_scores = qrecs['pre_risk_score'].tolist()
        fig_before.add_trace(go.Bar(
            x=pre_scores, y=names, orientation='h',
            marker=dict(
                color=pre_scores,
                colorscale=[[0,'#F97316'],[0.5,'#DC2626'],[1,'#7F1D1D']],
                showscale=False,
                line=dict(color='rgba(0,0,0,0)'),
            ),
            text=[f"{s:.0f}" for s in pre_scores],
            textposition='outside',
            textfont=dict(color='#EF4444', size=11, weight=700),
            hovertemplate='<b>%{y}</b><br>Pre-Risk Score: %{x:.1f}<extra></extra>',
        ))
        fig_before.update_layout(
            paper_bgcolor=DARK_BG, plot_bgcolor='rgba(30,41,59,0.5)',
            font=dict(family=FONT_FAM, color=TEXT_COL),
            xaxis=dict(gridcolor='rgba(148,163,184,0.06)', range=[0,120],
                       tickfont=dict(size=10,color=TEXT_COL), title='Risk Score'),
            yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=10,color='#F1F5F9'), autorange='reversed'),
            margin=dict(t=10, b=10, l=5, r=50), height=300, showlegend=False)
        st.plotly_chart(fig_before, width="stretch")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_after:
        st.markdown('<div class="graph-card"><div style="font-size:0.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#22C55E;margin-bottom:0.5rem;">AFTER QUARANTINE</div>', unsafe_allow_html=True)
        fig_after = go.Figure()
        post_scores = qrecs['post_risk_score'].fillna(0).tolist()
        fig_after.add_trace(go.Bar(
            x=post_scores, y=names, orientation='h',
            marker=dict(
                color=post_scores,
                colorscale=[[0,'#16A34A'],[0.5,'#15803D'],[1,'#14532D']],
                showscale=False,
                line=dict(color='rgba(0,0,0,0)'),
            ),
            text=[f"{s:.0f}" for s in post_scores],
            textposition='outside',
            textfont=dict(color='#22C55E', size=11, weight=700),
            hovertemplate='<b>%{y}</b><br>Post-Risk Score: %{x:.1f}<extra></extra>',
        ))
        fig_after.update_layout(
            paper_bgcolor=DARK_BG, plot_bgcolor='rgba(30,41,59,0.5)',
            font=dict(family=FONT_FAM, color=TEXT_COL),
            xaxis=dict(gridcolor='rgba(148,163,184,0.06)', range=[0,120],
                       tickfont=dict(size=10,color=TEXT_COL), title='Risk Score'),
            yaxis=dict(gridcolor='rgba(0,0,0,0)', tickfont=dict(size=10,color='#F1F5F9'), autorange='reversed'),
            margin=dict(t=10, b=10, l=5, r=50), height=300, showlegend=False)
        st.plotly_chart(fig_after, width="stretch")
        st.markdown('</div>', unsafe_allow_html=True)

    # Summary metrics
    avg_reduction = (qrecs['pre_risk_score'] - qrecs['post_risk_score'].fillna(0)).mean()
    total_tokens  = qrecs['tokens_revoked'].sum()
    total_privs   = qrecs['privileges_removed'].sum()
    st.markdown(f"""
    <div style="display:flex;gap:1rem;margin-top:0.75rem;flex-wrap:wrap;">
        <div style="flex:1;background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.2);
                    border-radius:10px;padding:0.8rem 1rem;text-align:center;">
            <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.3rem;">Avg Risk Reduction</div>
            <div style="font-size:1.4rem;font-weight:800;color:#22C55E;">↓ {avg_reduction:.1f}</div>
        </div>
        <div style="flex:1;background:rgba(59,130,246,0.08);border:1px solid rgba(59,130,246,0.2);
                    border-radius:10px;padding:0.8rem 1rem;text-align:center;">
            <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.3rem;">Tokens Revoked</div>
            <div style="font-size:1.4rem;font-weight:800;color:#3B82F6;">{int(total_tokens)}</div>
        </div>
        <div style="flex:1;background:rgba(249,115,22,0.08);border:1px solid rgba(249,115,22,0.2);
                    border-radius:10px;padding:0.8rem 1rem;text-align:center;">
            <div style="font-size:0.6rem;text-transform:uppercase;letter-spacing:1px;color:#64748B;margin-bottom:0.3rem;">Privileges Removed</div>
            <div style="font-size:1.4rem;font-weight:800;color:#F97316;">{int(total_privs)}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)
