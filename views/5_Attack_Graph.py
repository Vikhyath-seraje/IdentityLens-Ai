import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import networkx as nx
import plotly.graph_objects as go
from backend.attack_graph import AttackGraphGenerator
from backend.risk_engine import RiskEngine

# ── Page header ─────────────────────────────────────────────────────────────────
st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Threat Intelligence</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Attack Graph</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">
            Visualise identity attack paths and potential lateral movement across the enterprise.
        </p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(109,40,217,0.06);border:1px solid rgba(109,40,217,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#6D28D9;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">GRAPH ANALYSIS</span>
</div>
</div>
<style>
@keyframes fadeSlideUp {
    from{opacity:0;transform:translateY(14px)}
    to{opacity:1;transform:translateY(0)}
}
.graph-card {
    background:white;border:1px solid #E0E0E0;border-radius:10px;
    padding:1rem;box-shadow:0 1px 4px rgba(0,0,0,0.06);
    animation:fadeSlideUp 0.4s ease both;transition:box-shadow 0.25s;
}
.graph-card:hover { box-shadow:0 6px 20px rgba(0,0,0,0.1); }
.section-title h2 {
    font-size:1.0rem;font-weight:700;color:#1A1A1A;margin:1.6rem 0 0.8rem;
    padding-bottom:0.4rem;border-bottom:2px solid #E60028;display:inline-block;
}
.kpi-insight { font-size:0.72rem;color:#6B6B6B;margin-top:0.25rem;line-height:1.4; }
.legend-dot {
    width:12px;height:12px;border-radius:50%;display:inline-block;flex-shrink:0;
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)

@st.cache_data(ttl=300)
def load_graph():
    generator = AttackGraphGenerator()
    return generator.generate_graph()

@st.cache_data(ttl=300)
def get_high_risk_ids():
    risk_df = RiskEngine().calculate_risk_scores()
    return risk_df[risk_df['risk_level'].isin(['Critical', 'High'])]['identity_id'].tolist()

G = load_graph()
identity_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'Identity']

# ── Stats Row ───────────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Nodes", G.number_of_nodes())
    st.markdown('<div class="kpi-insight">Entities in the graph</div>', unsafe_allow_html=True)
with col2:
    st.metric("Total Edges", G.number_of_edges())
    st.markdown('<div class="kpi-insight">Access relationships</div>', unsafe_allow_html=True)
with col3:
    st.metric("Identity Nodes", len(identity_nodes))
    st.markdown('<div class="kpi-insight">Traceable identities</div>', unsafe_allow_html=True)
with col4:
    high_risk_ids = get_high_risk_ids()
    st.metric("High/Critical IDs", len(high_risk_ids))
    st.markdown('<div class="kpi-insight">Require path tracing</div>', unsafe_allow_html=True)

st.markdown("""
<div style="background:rgba(109,40,217,0.04);border:1px solid rgba(109,40,217,0.15);
            border-radius:8px;padding:0.65rem 1rem;margin:0.8rem 0;font-size:0.83rem;color:#4A4A4A;">
    <strong>How to use this graph:</strong> Select an identity below to trace their full access path —
    from user account → group memberships → role assignments → platform access.
    This reveals potential privilege escalation routes an attacker could exploit.
</div>
""", unsafe_allow_html=True)

st.divider()

# ── Controls ─────────────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Graph Controls</h2></div>', unsafe_allow_html=True)

col_sel, col_layout, col_size = st.columns([3, 1, 1])
with col_sel:
    selected_identity = st.selectbox(
        "Trace attack path for identity:",
        ['High/Critical Risk Only', 'All (Full Graph)'] + identity_nodes,
        help="Select a specific identity to see their complete access path."
    )
with col_layout:
    layout_algo = st.selectbox("Layout", ["spring", "kamada_kawai", "circular"],
                                help="Graph layout algorithm — spring works best for most cases")
with col_size:
    node_scale = st.slider("Node size", min_value=8, max_value=30, value=16, step=2)

# Determine subgraph
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
    nodes_to_keep = set([selected_identity])
    if selected_identity in G:
        try:
            nodes_to_keep.update(nx.descendants(G, selected_identity))
        except Exception:
            pass
    subG = G.subgraph(nodes_to_keep)

if subG.number_of_nodes() > 600:
    st.warning("The full graph is very large to render all at once. Please select a specific identity or 'High/Critical Risk Only' to trace a focused path.")
else:
    n_nodes = subG.number_of_nodes()
    n_edges = subG.number_of_edges()
    st.markdown(
        f'<div style="font-size:0.8rem;color:#6B6B6B;margin-bottom:0.5rem;">'
        f'Rendering graph with <strong style="color:#1A1A1A">{n_nodes} nodes</strong> '
        f'and <strong style="color:#1A1A1A">{n_edges} edges</strong>'
        f'</div>',
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

    # Color and size maps
    color_map = {
        'Identity': '#E60028',   # SocGen red — most important
        'Group':    '#16A34A',   # green
        'Role':     '#D97706',   # amber
        'Platform': '#1a56db',   # blue
    }
    size_map = {
        'Identity': int(node_scale * 1.3),
        'Group':    int(node_scale * 0.85),
        'Role':     int(node_scale * 0.85),
        'Platform': int(node_scale * 1.15),
    }
    symbol_map = {
        'Identity': 'circle',
        'Group':    'diamond',
        'Role':     'square',
        'Platform': 'star',
    }

    # Build traces per node type for proper legend
    fig = go.Figure()

    # Add edges first
    edge_x, edge_y = [], []
    for edge in subG.edges():
        if edge[0] in pos and edge[1] in pos:
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.2, color='rgba(100,116,139,0.25)'),
        hoverinfo='none', mode='lines', showlegend=False, name='Edge'
    ))

    # Add one trace per node type
    for ntype, clr in color_map.items():
        node_x, node_y, node_hover = [], [], []
        for node in subG.nodes():
            if node not in pos:
                continue
            if subG.nodes[node].get('type', 'Unknown') != ntype:
                continue
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            nlabel = subG.nodes[node].get('label', str(node))
            node_hover.append(f"<b>{ntype}</b><br>{nlabel}")

        if not node_x:
            continue

        show_text = n_nodes < 40
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text' if show_text else 'markers',
            name=ntype,
            text=[subG.nodes[n].get('label', str(n)) for n in subG.nodes()
                  if n in pos and subG.nodes[n].get('type') == ntype] if show_text else [],
            textposition="top center",
            textfont=dict(size=9, color='#1A1A1A'),
            hoverinfo='text',
            hovertext=node_hover,
            marker=dict(
                color=clr,
                size=size_map.get(ntype, node_scale),
                symbol=symbol_map.get(ntype, 'circle'),
                opacity=0.9,
                line=dict(width=2, color='white'),
            ),
        ))

    fig.update_layout(
        showlegend=True,
        legend=dict(
            orientation='v', yanchor='top', y=1, xanchor='left', x=1.01,
            font=dict(size=12, color='#1A1A1A', family='Inter, sans-serif'),
            bgcolor='rgba(255,255,255,0.95)',
            bordercolor='#E0E0E0', borderwidth=1,
            itemsizing='constant',
        ),
        hovermode='closest',
        paper_bgcolor='rgba(255,255,255,0)',
        plot_bgcolor='rgba(248,249,250,0.8)',
        margin=dict(b=10, l=5, r=130, t=10),
        height=580,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, mirror=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False,
                   showline=False, mirror=False),
    )

    st.markdown('<div class="graph-card">', unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # ── Legend explanation ───────────────────────────────────────────────────────
    st.markdown("""
    <div style="display:flex;gap:2rem;align-items:flex-start;flex-wrap:wrap;
                margin-top:0.75rem;padding:0.9rem 1.2rem;
                background:white;border:1px solid #E0E0E0;border-radius:10px;
                box-shadow:0 1px 4px rgba(0,0,0,0.05);">
        <div>
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                        color:#6B6B6B;margin-bottom:0.5rem;font-weight:700;">Node Types</div>
            <div style="display:flex;flex-direction:column;gap:0.4rem;">
                <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.82rem;color:#1A1A1A;">
                    <span style="width:12px;height:12px;border-radius:50%;background:#E60028;display:inline-block;flex-shrink:0;"></span>
                    <strong>Identity</strong> — User or service account being traced
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.82rem;color:#1A1A1A;">
                    <span style="width:12px;height:12px;background:#16A34A;display:inline-block;flex-shrink:0;transform:rotate(45deg);"></span>
                    <strong>Group</strong> — AD or Okta group membership
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.82rem;color:#1A1A1A;">
                    <span style="width:12px;height:12px;background:#D97706;display:inline-block;flex-shrink:0;border-radius:2px;"></span>
                    <strong>Role</strong> — IAM role or permission set
                </div>
                <div style="display:flex;align-items:center;gap:0.5rem;font-size:0.82rem;color:#1A1A1A;">
                    <span style="width:12px;height:12px;background:#1a56db;display:inline-block;flex-shrink:0;clip-path:polygon(50% 0%,61% 35%,98% 35%,68% 57%,79% 91%,50% 70%,21% 91%,32% 57%,2% 35%,39% 35%);"></span>
                    <strong>Platform</strong> — AWS, AD, or Okta destination
                </div>
            </div>
        </div>
        <div style="border-left:1px solid #E0E0E0;padding-left:2rem;">
            <div style="font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;
                        color:#6B6B6B;margin-bottom:0.5rem;font-weight:700;">Reading the Graph</div>
            <div style="font-size:0.82rem;color:#4A4A4A;line-height:1.6;max-width:340px;">
                Edges represent <strong>access relationships</strong>. Follow the path from an
                Identity → Group → Role → Platform to understand what that identity
                can access and whether it represents an escalation risk.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
