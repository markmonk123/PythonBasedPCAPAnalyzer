from geoip2.webservice import Client

def query_maxmind_api(ip_address, account_id, api_key):
    """
    Query MaxMind GeoIP services via their online API for geographic information.
    :param ip_address: The IP address to query.
    :param account_id: MaxMind account ID for accessing the API.
    :param api_key: MaxMind API key for accessing the API.
    :return: Dictionary containing location data for the IP address (or None if not found).
    """
    try:
        # Initialize MaxMind API client
        client = Client(account_id, api_key)
        
        # Query the API for geographic information
        response = client.city(ip_address)

        # Extract relevant data from the API response
        location_data = {
            "ip": ip_address,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
            "city": response.city.name,
            "country": response.country.name,
            "organization": response.traits.autonomous_system_organization
        }
        return location_data

    except Exception as e:
        print(f"Error querying MaxMind API for IP {ip_address}: {e}")
        return None