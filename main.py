from analyze import (
    run_multiple_traceroutes, build_global_asn_graph,
    find_shortest_path_for_targets, visualize_mixed_asn_connections,
    compute_all_pairs_shortest_paths
)

if __name__ == "__main__":
    targets = [
        "2001:4860:4860::8888",  # Google's Public DNS (IPv6)
        "8.8.8.8",               # Google's Public DNS (IPv4)
        "2606:4700:4700::1111",  # Cloudflare DNS (IPv6)
        "1.1.1.1"                # Cloudflare DNS (IPv4)
    ]
    traceroute_results = run_multiple_traceroutes(targets)
    asn_graph, asn_mapping = build_global_asn_graph(traceroute_results)

    # Compute all-pairs shortest paths
    all_paths = compute_all_pairs_shortest_paths(asn_graph)

    # Example: visualize shortest path between any two targets
    source_target = "2001:4860:4860::8888"
    dest_target = "1.1.1.1"
    shortest_path, path_length = find_shortest_path_for_targets(
        asn_graph, traceroute_results, source_target, dest_target
    )
    if shortest_path:
        print(f"\nShortest path between {source_target} and {dest_target}:")
        print(" -> ".join(map(str, shortest_path)))
        print(f"Path length: {path_length}")
    else:
        print(f"No path found between {source_target} and {dest_target}.")

    visualize_mixed_asn_connections(asn_graph, traceroute_results, shortest_path=shortest_path)