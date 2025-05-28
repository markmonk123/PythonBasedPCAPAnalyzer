import pyshark
import pymongo
from pymongo import MongoClient

def analyze_pcap(file_path):
    """
    Analyzes a given pcap file and extracts BSSID, SSID, MAC addresses, destination addresses, etc.

    Args:
        file_path (str): Path to the .pcap file to be analyzed.

    Returns:
        List of dictionaries containing packet details.
    """
    try:
        print(f"Opening pcap file: {file_path}")
        packets = pyshark.FileCapture(file_path)
        packet_details = []

        for packet in packets:
            packet_info = {}

            if 'wlan' in packet:
                # Extract WiFi-specific fields
                packet_info['bssid'] = packet.wlan.bssid if hasattr(packet.wlan, 'bssid') else None
                packet_info['ssid'] = packet.wlan.ssid if hasattr(packet.wlan, 'ssid') else None

            if 'eth' in packet:
                # Extract Ethernet-specific fields
                packet_info['source_mac'] = packet.eth.src if hasattr(packet.eth, 'src') else None
                packet_info['destination_mac'] = packet.eth.dst if hasattr(packet.eth, 'dst') else None

            if 'ip' in packet:
                # Extract IP-specific fields
                packet_info['source_ip'] = packet.ip.src if hasattr(packet.ip, 'src') else None
                packet_info['destination_ip'] = packet.ip.dst if hasattr(packet.ip, 'dst') else None

            # Add extracted info to the list if valid
            if packet_info:
                packet_details.append(packet_info)

        packets.close()
        return packet_details

    except FileNotFoundError:
        print("Error: File not found. Please check the file path.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return []

def store_to_mongodb(packet_details, db_name, collection_name):
    """
    Stores packet details into a MongoDB database.

    Args:
        packet_details (list): List of dictionaries containing packet information.
        db_name (str): Name of the MongoDB database.
        collection_name (str): Name of the collection in the database.

    Returns:
        None
    """
    try:
        # Connect to local MongoDB server
        client = MongoClient('localhost', 27017)
        db = client[db_name]
        collection = db[collection_name]

        # Insert data into MongoDB collection
        if packet_details:
            collection.insert_many(packet_details)
            print(f"Successfully inserted {len(packet_details)} packets into the MongoDB collection.")
        else:
            print("No packet details to insert into the database.")

    except pymongo.errors.ConnectionFailure as e:
        print(f"Error: Could not connect to MongoDB. {e}")
    except pymongo.errors.OperationFailure as e:
        print(f"Error: Operation failed when interacting with MongoDB. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Example Usage
if __name__ == "__main__":
    file_path = "example.pcap"  # Replace with your pcap file path
    db_name = "network_analysis"  # Name of the MongoDB database
    collection_name = "packet_details"  # Name of the collection to store packet data

    print("Analyzing pcap file...")
    packet_data = analyze_pcap(file_path)

    print("Storing packet details into MongoDB...")
    store_to_mongodb(packet_data, db_name, collection_name)

    print("Done!")
    }