from pymongo import MongoClient

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

    return {"mac_data": mac_address_pairs, "bssid_data": bssid_data, "neighbor_solicitations": neighbor_solicitations}