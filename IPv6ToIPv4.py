import requests

def query_ripe_asn_history(resource):
    """
    Query RIPEstat ASN history to retrieve ASN information for a given IPv6 or IPv4 address.
    :param resource: Target IP address (IPv4 or IPv6).
    :return: ASN data (list of ASNs associated with the resource).
    """
    url = f"https://stat.ripe.net/data/asn-history/data.json?resource={resource}"
    response = requests.get(url)
    if response.status_code == 200:
        try:
            data = response.json()
            asns = data["data"]["asns"]
            return asns
        except KeyError:
            return None
    else:
        print("Error querying RIPEstat ASN history:", response.status_code)
        return None

def query_ripe_prefix_information(resource):
    """
    Query RIPEstat for prefix information of a given IPv6 or IPv4 address.
    :param resource: Target IP address or prefix (IPv4/IPv6).
    :return: Prefix data dictionary (ASN, routing data, etc.).
    """
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={resource}"
    response = requests.get(url)
    if response.status_code == 200:
        try:
            data = response.json()
            return data["data"]["prefixes"]
        except KeyError:
            return None
    else:
        print("Error querying RIPEstat Prefix Overview:", response.status_code)
        return None
        }