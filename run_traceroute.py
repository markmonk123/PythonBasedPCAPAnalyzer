
def run_traceroute_to_mongodb(target, db):
    """
    Run traceroute and store results into MongoDB.
    :param target: Target IP/domain.
    :param db: MongoDB database object.
    :return: List of hops with traceroute data.
    """
    print(f"\nPerforming traceroute for target: {target}")
    result = subprocess.run(["traceroute", "-n", target], capture_output=True, text=True)
    
    hops = []
    for line in result.stdout.splitlines():
        match = re.match(r"(\d+)\s+([\d\.]+)\s+.*?(\d+\.\d+)\sms", line)  # Parse traceroute output
        if match:
            hop_number = int(match[1])
            hop_ip = match[2]
            latency = float(match[3])
            hops.append({
                "hop_number": hop_number,
                "ip": hop_ip,
                "latency": latency
            })
    
    # Save traceroute into the "traceroute_data" collection
    save_to_mongodb(db["traceroute_data"], {"target": target, "hops": hops})
    return hops