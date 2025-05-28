from pymongo import MongoClient
import networkx as nx
import matplotlib.pyplot as plt
import pyshark

def run_multiple_traceroutes(targets):
    """
    Perform traceroutes for a list of targets (IPv4 and/or IPv6).
    :param targets: List of target IPs/domains.
    :return: Dictionary where keys are targets and values are lists of traceroute hops.
    """
    traceroute_results = {}
    for target in targets:
        is_ipv6 = ":" in target  # Simple heuristic for IPv6
        hops = run_traceroute(target, ipv6=is_ipv6)  # You must implement run_traceroute
        traceroute_results[target] = hops
    return traceroute_results

def build_global_asn_graph(traceroute_results):
    """
    Build a global ASN graph from traceroute results for multiple targets.
    :param traceroute_results: Dictionary of traceroute results (key=target, value=hops).
    :return: A NetworkX graph representing ASN connections and ASN mappings for all IPs.
    """
    G = nx.DiGraph()
    asn_mapping = {}
    for target, hops in traceroute_results.items():
        for i, hop in enumerate(hops):
            ip = hop["ip"]
            asns = query_asn_for_ip(ip)  # You must implement query_asn_for_ip
            if asns:
                asn = asns[0]
                asn_mapping[ip] = asn
                ip_type = "IPv6" if ":" in ip else "IPv4"
                G.add_node(asn, ip_type=ip_type)
                if i > 0:
                    prev_ip = hops[i - 1]["ip"]
                    prev_asn = asn_mapping.get(prev_ip, None)
                    if prev_asn is not None and prev_asn != asn:
                        G.add_edge(prev_asn, asn)
    return G, asn_mapping

def find_shortest_path_for_targets(graph, traceroute_results, source_target, dest_target):
    """
    Find the shortest path in the ASN graph between the final ASNs of two targets.
    """
    source_hops = traceroute_results[source_target]
    dest_hops = traceroute_results[dest_target]
    source_asn = query_asn_for_ip(source_hops[-1]["ip"])[0]
    dest_asn = query_asn_for_ip(dest_hops[-1]["ip"])[0]
    try:
        shortest_path = nx.shortest_path(graph, source=source_asn, target=dest_asn)
        path_length = nx.shortest_path_length(graph, source=source_asn, target=dest_asn)
        return shortest_path, path_length
    except nx.NetworkXNoPath:
        print("No path exists between the specified ASNs.")
        return None, None

def visualize_mixed_asn_connections(graph, traceroute_results, shortest_path=None):
    """
    Visualize ASN connections across all traceroute targets and highlight shortest paths.
    """
    pos = nx.spring_layout(graph)
    plt.figure(figsize=(12, 10))
    nx.draw(graph, pos, with_labels=True, node_size=1500, node_color="lightblue", font_size=8)
    if shortest_path:
        path_edges = list(zip(shortest_path, shortest_path[1:]))
        nx.draw_networkx_edges(graph, pos, edgelist=path_edges, edge_color="red", width=2)
        nx.draw_networkx_nodes(graph, pos, nodelist=shortest_path, node_color="yellow", node_size=2000)
    plt.title("Mixed IPv4/IPv6 ASN Connections and Paths")
    plt.show()

def save_to_mongodb(collection, data):
    """
    Save extracted data to a MongoDB collection.
    :param collection: MongoDB collection object.
    :param data: Data to store (dict or list of dicts).
    """
    if isinstance(data, list):
        collection.insert_many(data)  # Insert multiple documents
    else:
        collection.insert_one(data)  # Insert individual document

def analyze_pcap_to_mongodb(file_path, db):
    """
    Analyze Wireshark PCAP file and store results into MongoDB.
    :param file_path: Path to the PCAP file.
    :param db: MongoDB database object.
    """
    print(f"\nAnalyzing PCAP file: {file_path}")
    capture = pyshark.FileCapture(file_path, display_filter="wlan or eth or icmpv6")

    mac_address_pairs = []  # List to store MAC address pairs
    bssid_data = []         # List to store BSSID data
    neighbor_solicitations = []  # List to store ICMPv6 solicitation data
    
    # Process PCAP packets
    for packet in capture:
        try:
            # Extract MAC addresses for Ethernet frames
            if hasattr(packet, 'eth'):
                mac_address_pairs.append({
                    "source_mac": packet.eth.src,
                    "destination_mac": packet.eth.dst
                })
            
            # Extract Wireless (Wi-Fi) frames
            elif hasattr(packet, 'wlan'):
                bssid = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else None
                ssid = packet.wlan.ssid.strip() if hasattr(packet.wlan, 'ssid') and packet.wlan.ssid.strip() else None
                
                bssid_data.append({
                    "bssid": bssid,
                    "ssid": ssid,
                    "source_mac": packet.wlan.ta,
                    "destination_mac": packet.wlan.ra
                })
            
            # Extract ICMPv6 Neighbor Solicitation messages
            if hasattr(packet, 'icmpv6') and 'neighbor solicitation' in packet.icmpv6.type.lower():
                neighbor_solicitations.append({
                    "source_ipv6": packet.ipv6.src,
                    "target_ipv6": packet.icmpv6.nd_target_address
                })
        except AttributeError:
            continue  # Skip invalid packets
    
    capture.close()

    # Save results into collections
    save_to_mongodb(db["mac_data"], mac_address_pairs)
    save_to_mongodb(db["bssid_data"], bssid_data)
    save_to_mongodb(db["neighbor_solicitations"], neighbor_solicitations)

    return {
        "mac_data": mac_address_pairs,
        "bssid_data": bssid_data,
        "neighbor_solicitations": neighbor_solicitations
    }