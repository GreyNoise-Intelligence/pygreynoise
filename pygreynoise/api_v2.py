import requests
import json

class GreyNoiseAPI(api_key):
    def __init__(self):
        # Initiates the class, setting the API key and establishing the base request URL
        self.key = api_key
        self.header = {'key': self.key}
        self.base = "https://research.api.greynoise.io"

    def meta_ping(self):
        # Check whether your API key works
        endpoint = "/v2/meta/ping"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r

    def research_time_series_scan(self, protocol, port):
        # Use this endpoint to query GreyNoise for the amount of unique IPs that have scanned the Internet for a given port/protocol pair over the past 90 days
        endpoint = "/v2/research/time_series/scan/{protocol}/{port}".format(protocol = protocol, port = port)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_tag_list(self):
        # Use this endpoint to list all of the available GreyNoise tags
        endpoint = "/v2/research/tag/list"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()['tags']

    def research_tag_single(self, tag, offset = None):
        # Use this endpoint to query all of the IPs that have a given tag over the past 30 days
        # OPTIONAL: Accepts an offset for pagination
        endpoint = "/v2/research/tag/single"
        request = "{}{}".format(self.base, endpoint)
        data = json.dumps({"tag": tag})
        if offset:
            request = "{}?offset={}".format(request, offset)
            r = requests.get(request, headers = self.header, data = data)
        else:
            r = requests.get(request, headers = self.header, data = data)
        return r.json()

    def research_tag_combination(self, include = None, exclude = None, offset = None):
        # Use this endpoint to query IPs that have a combination of different tags.
        # Include and Exclude accept multiple tags in the form of a list e.g. exclude = ['RDP Scanner', 'Shodan.io']
        # OPTIONAL: Accepts an offset for pagination
        endpoint = "/v2/research/tag/combination"
        request = "{}{}".format(self.base, endpoint)
        data = {"query": []}
        if include:
            for item in include:
                data["query"].append("+{}".format(item))
        if exclude:
            for item in exclude:
                data["query"].append("-{}".format(item))
        data = json.dumps(data)
        if offset:
            request = "{}?offset={}".format(request, offset)
            r = requests.get(request, headers = self.header, data = data)
        else:
            r = requests.get(request, headers = self.header, data = data)
        return r.json()['ips']

    def research_ip_summary(self, ip):
        # Get tags, metadata, time ranges, port/protocols, HTTP paths, and useragents belonging to a given IP address
        endpoint = "/v2/research/ip/{ip}".format(ip=ip)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_raw_data(self, protocol, port):
        # Get raw IP addresses and time ranges of all IPs that scanned the Internet for a given port/protocol pair in the past three days.
        endpoint = "/v2/research/raw/scan/{protocol}/{port}".format(protocol = protocol, port = port)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_stats_top_scan(self):
        # Get a list of the port/protocol pairs that are most commonly being scanned for over the past 24 hours.
        endpoint = "/v2/research/stats/top/scan"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_stats_top_http_path(self):
        # Get a list of the HTTP paths that are most commonly being scanned for over the past 24 hours.
        endpoint = "/v2/research/stats/top/http/path"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_stats_top_http_useragent(self):
        # Get a list of the HTTP useragents that are most commonly being used in web crawlers for over the past 24 hours.
        endpoint = "/v2/research/stats/top/http/useragent"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_stats_top_org(self):
        # Get a list of the owners of the organizations most commonly observed scanning the Internet over the past 24 hours.
        endpoint = "/v2/research/stats/top/org"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_stats_top_asn(self):
        # Get a list of the owners of the ASNs most commonly observed scanning the Internet over the past 24 hours.
        endpoint = "/v2/research/stats/top/asn"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def research_stats_top_rdns(self):
        # Get a list of the reverse DNS prefixes of the most commonly observed IPs scanning the Internet over the past 24 hours.
        endpoint = "/v2/research/stats/top/rdns"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def research_search_org(self, org):
        # Search for Internet scanners by organization name
        endpoint = "/v2/research/search/org"
        request = "{}{}".format(self.base, endpoint)
        data = json.dumps({"search": org})
        r = requests.get(request, headers = self.header, data = data)
        return r.json()
    
    def research_actors(self):
        # Get the IP addresses of all the currently labeled benign mass-scanning actors (Such as Shodan, Project Sonar, Censys, etc) over the past 30 days
        endpoint = "/v2/research/actors"
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def infections_cidr(self, block, bits):
        # Identify compromised devices in a given CIDR block active over the past 30 days
        endpoint = "/v2/infections/cidr/{block}/{bits}".format(block = block, bits = bits)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def infections_asn(self, asn):
        # Identify compromised devices in a given ASN active over the past 30 days
        endpoint = "/v2/infections/asn/{asn}".format(asn = asn)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def infections_search_org(self, org):
        # Search for compromised devices in a given organization active over the past 30 days
        endpoint = "/v2/infections/search/org"
        request = "{}{}".format(self.base, endpoint)
        data = json.dumps({"search": org})
        r = requests.get(request, headers = self.header, data = data)
        return r.json()

    def research_scanners_cidr(self, block, bits):
        # Query a CIDR block for Internet scanners active over the past 30 days
        endpoint = "/v2/research/scanners/cidr/{block}/{bits}".format(block = block, bits = bits)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def research_scanners_asn(self, asn):
        # Query an ASN for Internet scanners active over the past 30 days
        endpoint = "/v2/research/scanners/asn/{asn}".format(asn = asn)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def research_ja3_fingerprint(self, fingerprint):
        # Query all Internet scanners to exhibit a given JA3 fingerprint
        endpoint = "/v2/research/ja3/fingerprint/{fingerprint}".format(fingerprint = fingerprint)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()
    
    def research_ja3_ip(self, ip):
        # Query all JA3 fingerprints exhibited by a given Internet scanner
        endpoint = "/v2/research/ja3/ip/{ip}".format(ip = ip)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def enterprise_noise_quick(self, ip):
        # Query whether a given IP address has scanned the Internet or not and how likely the scan traffic was spoofed.
        endpoint = "/v2/enterprise/noise/quick/{ip}".format(ip = ip)
        request = "{}{}".format(self.base, endpoint)
        r = requests.get(request, headers = self.header)
        return r.json()

    def enterprise_noise_multi_quick(self, ip_addresses):
        #  Query whether a given IP address has scanned the Internet or not and how likely the scan traffic was spoofed.
        # NOTE: ip_addresses accepts a list e.g. ip_addresses = ["1.1.1.1", "2.2.2.2"]
        endpoint = "/v2/enterprise/noise/multi/quick"
        request = "{}{}".format(self.base, endpoint)
        data = json.dumps({"ips": ip_addresses})
        r = requests.get(request, headers = self.header, data = data)
        return r.json()
