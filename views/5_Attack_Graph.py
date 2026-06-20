import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import networkx as nx
import plotly.graph_objects as go
from backend.attack_graph import AttackGraphGenerator

st.markdown("""
<div style="padding:1.8rem 2.5rem 0;max-width:1440px;margin:0 auto;">
<div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;
            padding-bottom:1.2rem;border-bottom:1px solid #E0E0E0;margin-bottom:1.8rem;">
    <div>
        <div style="font-size:0.68rem;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;
                    color:#E60028;margin-bottom:0.3rem;">Threat Intelligence</div>
        <h1 style="font-size:1.55rem;font-weight:800;color:#1A1A1A;margin:0 0 0.25rem;letter-spacing:-0.3px;">
            Attack Graph</h1>
        <p style="font-size:0.875rem;color:#6B6B6B;margin:0;">Visualise identity attack paths and lateral movement across the enterprise.</p>
    </div>
    <span style="display:inline-flex;align-items:center;padding:0.25rem 0.75rem;
                background:rgba(109,40,217,0.06);border:1px solid rgba(109,40,217,0.2);
                border-radius:100px;font-size:0.68rem;font-weight:700;color:#6D28D9;
                letter-spacing:0.8px;text-transform:uppercase;margin-top:0.2rem;">GRAPH ANALYSIS</span>
</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="padding:0 2.5rem 2.5rem;max-width:1440px;margin:0 auto;">', unsafe_allow_html=True)
@st.cache_data
def load_graph():
    generator = AttackGraphGenerator()
    return generator.generate_graph()

G = load_graph()

# ── Graph stats ────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns(3)
with col1:
    st.metric("🔵 Total Nodes", G.number_of_nodes())
with col2:
    st.metric("🔗 Total Edges", G.number_of_edges())
with col3:
    identity_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'Identity']
    st.metric("👤 Identity Nodes", len(identity_nodes))

st.divider()

# ── Controls ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-title"><h2>Graph Controls</h2></div>', unsafe_allow_html=True)

col_sel, col_layout = st.columns([3, 1])
with col_sel:
    selected_identity = st.selectbox(
        "Trace attack path for identity:",
        ['All (Full Graph)'] + identity_nodes,
        help="Select a specific identity to see their complete access path to platforms and resources."
    )
with col_layout:
    layout_algo = st.selectbox("Layout", ["spring", "kamada_kawai", "circular"], help="Graph layout algorithm")

if selected_identity != 'All (Full Graph)':
    nodes_to_keep = set([selected_identity])
    try:
        descendants = nx.descendants(G, selected_identity)
        nodes_to_keep.update(descendants)
    except Exception:
        pass
    subG = G.subgraph(nodes_to_keep)
else:
    subG = G

if subG.number_of_nodes() > 600:
    st.warning("⚠️ The full graph is too large to render. Please select a specific identity to trace their path.")
else:
    st.markdown(f'<div style="font-size:0.8rem;color:#64748b;margin-bottom:0.5rem;">Rendering graph with <strong style="color:#e2e8f0;">{subG.number_of_nodes()}</strong> nodes and <strong style="color:#e2e8f0;">{subG.number_of_edges()}</strong> edges</div>', unsafe_allow_html=True)

    # Layout
    seed = 42
    try:
        if layout_algo == "spring":
            pos = nx.spring_layout(subG, seed=seed, k=2)
        elif layout_algo == "kamada_kawai":
            pos = nx.kamada_kawai_layout(subG)
        else:
            pos = nx.circular_layout(subG)
    except Exception:
        pos = nx.spring_layout(subG, seed=seed)

    # Edges
    edge_x, edge_y = [], []
    for edge in subG.edges():
        if edge[0] in pos and edge[1] in pos:
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='rgba(139,92,246,0.25)'),
        hoverinfo='none', mode='lines'
    )

    # Node colour & size by type
    color_map = {
        'Identity': '#00d4ff',
        'Group':    '#10b981',
        'Role':     '#f59e0b',
        'Platform': '#ef4444',
    }
    size_map = {'Identity': 18, 'Group': 12, 'Role': 12, 'Platform': 16}

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for node in subG.nodes():
        if node not in pos:
            continue
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        ntype  = subG.nodes[node].get('type', 'Unknown')
        nlabel = subG.nodes[node].get('label', str(node))
        node_text.append(f"<b>{ntype}</b><br>{nlabel}")
        node_color.append(color_map.get(ntype, '#64748b'))
        node_size.append(size_map.get(ntype, 10))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        hovertext=node_text,
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=1.5, color='rgba(0,0,0,0.4)'),
            opacity=0.9,
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            showlegend=False,
            hovermode='closest',
            paper_bgcolor='rgba(255,255,255,0)',
            plot_bgcolor='rgba(255,255,255,0)',
            margin=dict(b=20, l=5, r=5, t=20),
            height=560,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        )
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Legend ─────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="display:flex;gap:1.5rem;align-items:center;margin-top:0.5rem;padding:0.8rem 1rem;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:10px;">
        <span style="font-size:0.75rem;color:#64748b;letter-spacing:1px;text-transform:uppercase;">Legend</span>
        <span style="display:flex;align-items:center;gap:0.4rem;font-size:0.82rem;color:#e2e8f0;"><span style="width:12px;height:12px;border-radius:50%;background:#00d4ff;display:inline-block;"></span>Identity</span>
        <span style="display:flex;align-items:center;gap:0.4rem;font-size:0.82rem;color:#e2e8f0;"><span style="width:12px;height:12px;border-radius:50%;background:#10b981;display:inline-block;"></span>Group</span>
        <span style="display:flex;align-items:center;gap:0.4rem;font-size:0.82rem;color:#e2e8f0;"><span style="width:12px;height:12px;border-radius:50%;background:#f59e0b;display:inline-block;"></span>Role</span>
        <span style="display:flex;align-items:center;gap:0.4rem;font-size:0.82rem;color:#e2e8f0;"><span style="width:12px;height:12px;border-radius:50%;background:#ef4444;display:inline-block;"></span>Platform</span>
    </div>
    """, unsafe_allow_html=True)
