# Alpha API endpoints. 
import json
import requests

# thank you https://github.com/phyler/greynoise for the base functions!

# List GreyNoise Intelligence Tags
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
        if 'tags' in r.json():
            return r.json()['tags']
        else:
            print("No tags found.")
    else:
        return {}
#########################################################################################



# Query all tags associated with a given IP address
#
# GreyNoise adds scanner tags to IP addresses. This function retrieves
# all tags currently in use.
#########################################################################################
def query_ip(ip, key=False):
    """Retrieves GreyNoise tags associated with a given IP address.
    :param ip: The IP address to use in the query.
    :type ip: str
    :return: List of GreyNoise tags associated with the supplied IP address.
    :rtype: list
    """
    r = requests.post('http://api.greynoise.io:8888/v1/query/ip', ({'ip': ip, 'key': key}))
    if r.status_code == 200:
        if 'records' in r.json():
            return r.json()['records']
        else:
            print("No records found.")
    else:
        return {}


def query_ips(ips, key=False):
    """Retrieves GreyNoise tags associated with a list of IP addresses.
    :param ips: List of IPs to query for GreyNoise tags.
    :type ips: list
    :return: Combined list of GreyNoise tags associated with each IP address in list.
    :rtype: list
    """
    ips_list = []
    for ip in ips:
        r = requests.post('http://api.greynoise.io:8888/v1/query/ip', ({'ip': ip, 'key': key}))
        if r.status_code == 200:
            if 'records' in r.json():
                ips_list.extend(r.json()['records'])
            else:
                print("No records found.")
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
def query_tag(tag, key=False):
    """Retrieves IPs associated with a given GreyNoise tag.
    :param ips: Tag to use in query.
    :type ips: str
    :return: List of IP addresses associated with the given GreyNoise tag.
    :rtype: list
    """
    r = requests.post('http://api.greynoise.io:8888/v1/query/tag', ({'tag': tag, 'key': key}))
    if r.status_code == 200:
        if 'records' in r.json():
            return r.json()['records']
        else:
            print("No records found.")
    else:
        return {}

def query_tags(tags, key=False):
    """Retrieves IPs associated with a list of GreyNoise tags.
    :param ips: List of tags to use in query.
    :type ips: list
    :return: Combined list of IP addresses associated with each in list of GreyNoise tags.
    :rtype: list
    """
    tags_list = []
    for tag in tags:
        r = requests.post('http://api.greynoise.io:8888/v1/query/tag', ({'tag': tag, 'key': key}))
        if r.status_code == 200:
            if 'records' in r.json():
                tags_list.extend(r.json()['records'])
        else:
            tags_list.extend([])
    if not tags_list:
        print("No records found.")
    return tags_list
#########################################################################################