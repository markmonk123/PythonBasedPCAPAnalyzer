if __name__ == "__main__":
    # Example IPv6 and IPv4 addresses for analysis
    ipv6_address = "2001:4860:4860::8888"  # Google's Public DNS IPv6
    ipv4_address = "8.8.8.8"              # Google's Public DNS IPv4

    # Analyze IPv6 → IPv4 transitions
    transition_data = analyze_ipv6_to_ipv4_transition(ipv6_address, ipv4_address)

    # Visualize the transition
    visualize_ipv6_ipv4_transition_analysis(
        transition_data["ipv6_asns"], 
        transition_data["ipv4_asns"], 
        transition_data["common_asns"]
    )