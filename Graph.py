import networkx as nx
import matplotlib.pyplot as plt

def visualize_ipv6_ipv4_transition_analysis(ipv6_asns, ipv4_asns, common_asns):
    """
    Visualize ASN transitions between IPv6 and IPv4 using NetworkX.
    :param ipv6_asns: List of ASNs for IPv6.
    :param ipv4_asns: List of ASNs for IPv4.
    :param common_asns: Set of ASNs shared between IPv6 and IPv4.
    """
    print("\nVisualizing ASN transitions between IPv6 and IPv4...")
    G = nx.Graph()

    # Add IPv6 ASNs to the graph
    for asn in ipv6_asns:
        G.add_node(f"IPv6_AS{asn}", color="blue")
    
    # Add IPv4 ASNs to the graph
    for asn in ipv4_asns:
        G.add_node(f"IPv4_AS{asn}", color="green")
    
    # Add edges for common ASNs
    for asn in common_asns:
        G.add_edge(f"IPv6_AS{asn}", f"IPv4_AS{asn}")

    # Node color mapping
    node_colors = [data['color'] for _, data in G.nodes(data=True)]

    # Draw the graph
    plt.figure(figsize=(10, 6))
    nx.draw(
        G, with_labels=True, node_color=node_colors, node_size=5000, font_size=10,
        font_weight="bold", edge_color="gray", style="dashed", pos=nx.spring_layout(G)
    )
    plt.title("ASN Transition Analysis: IPv6 to IPv4")
    plt.show()