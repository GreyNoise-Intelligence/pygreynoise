# Alpha API endpoints. 
import requests


# List GreyNoise Intelligence Tags
#
# GreyNoise adds scanner tags to IP addresses. This function retrieves
# all tags currently in use.
#########################################################################################
def list_tags():
    """Retrieves GreyNoise scanner tags.
    :returns: List of all GreyNoise scanner tags currently in use.
    :rtype: list
    """
    r = requests.get('http://api.greynoise.io:8888/v1/query/list')
    if r.status_code == 200:
        return r.json()['tags']
    else:
        return {}
#########################################################################################



# Query all tags associated with a given IP address
#
# GreyNoise adds scanner tags to IP addresses. This function retrieves
# all tags currently in use.
#########################################################################################
def query_ip(ip):
    """Retrieves GreyNoise tags associated with a given IP address.
    :param ip: The IP address to use in the query.
    :type ip: str
    :return: List of GreyNoise tags associated with the supplied IP address.
    :rtype: list
    """
    r = requests.post('http://api.greynoise.io:8888/v1/query/ip', ({'ip': ip}))
    if r.status_code == 200:
        return r.json()['records']
    else:
        return {}


def query_ips(ips):
    """Retrieves GreyNoise tags associated with a list of IP addresses.
    :param ips: List of IPs to query for GreyNoise tags.
    :type ips: list
    :return: Combined list of GreyNoise tags associated with each IP address in list.
    :rtype: list
    """
    ips_list = []
    for ip in ips:
        r = requests.post('http://api.greynoise.io:8888/v1/query/ip', ({'ip': ip}))
        if r.status_code == 200:
            ips_list.extend(r.json()['records'])
        else:
            ips_list.extend([])

    return ips_list
#########################################################################################




# Query all IPs that have a given tag
#
# GreyNoise adds scanner tags to IP addresses. This function retrieves
# all tags currently in use.
#
#########################################################################################
def query_tag(tag):
    """Retrieves IPs associated with a given GreyNoise tag.
    :param ips: Tag to use in query.
    :type ips: str
    :return: List of IP addresses associated with the given GreyNoise tag.
    :rtype: list
    """
    r = requests.post('http://api.greynoise.io:8888/v1/query/tag', ({'tag': tag}))
    if r.status_code == 200:
        return r.json()['records']
    else:
        return {}

def query_tags(tags):
    """Retrieves IPs associated with a list of GreyNoise tags.
    :param ips: List of tags to use in query.
    :type ips: list
    :return: Combined list of IP addresses associated with each in list of GreyNoise tags.
    :rtype: list
    """
    tags_list = []
    for tag in tags:
        r = requests.post('http://api.greynoise.io:8888/v1/query/tag', ({'tag': tag}))
        if r.status_code == 200:
            tags_list.extend(r.json()['records'])
        else:
            tags_list.extend([])

    return tags_list
#########################################################################################