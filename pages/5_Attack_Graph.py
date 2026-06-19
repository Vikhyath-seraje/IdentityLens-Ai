import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import streamlit as st
import networkx as nx
import plotly.graph_objects as go
from backend.attack_graph import AttackGraphGenerator

st.title("Attack Graph Visualization")

@st.cache_data
def load_graph():
    generator = AttackGraphGenerator()
    return generator.generate_graph()

G = load_graph()

st.markdown("Visualizes identities, groups, roles, and platforms to identify privilege escalation paths.")

# Filter graph for a specific identity to reduce clutter
identity_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'Identity']
selected_identity = st.selectbox("Select an Identity to trace their attack path:", ['All'] + identity_nodes)

if selected_identity != 'All':
    # Get subgraph connected to this identity
    nodes_to_keep = set([selected_identity])
    # Add all descendants (since we have directed edges Identity -> Role/Group -> Platform)
    descendants = nx.descendants(G, selected_identity)
    nodes_to_keep.update(descendants)
    subG = G.subgraph(nodes_to_keep)
else:
    subG = G

if subG.number_of_nodes() > 500:
    st.warning("The graph is too large to render completely. Please select a specific Identity.")
else:
    # Layout
    pos = nx.spring_layout(subG, seed=42)
    
    edge_x = []
    edge_y = []
    for edge in subG.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')
        
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    
    color_map = {
        'Identity': 'blue',
        'Group': 'green',
        'Role': 'orange',
        'Platform': 'red'
    }
    
    for node in subG.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_type = subG.nodes[node].get('type', 'Unknown')
        node_label = subG.nodes[node].get('label', str(node))
        node_text.append(f"{node_type}: {node_label}")
        node_color.append(color_map.get(node_type, 'gray'))
        
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=node_text,
        textposition="bottom center",
        marker=dict(
            showscale=False,
            color=node_color,
            size=15,
            line_width=2))
            
    fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                 )
                 
    st.plotly_chart(fig, use_container_width=True)
