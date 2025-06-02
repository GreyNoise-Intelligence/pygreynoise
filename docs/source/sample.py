from greynoise.api import APIConfig, GreyNoise

api_key = "<enter-api-key-here>"
ip_addresses = ["108.168.3.151", "8.8.8.8", "318.1.1.1"]
api_config = APIConfig(
    api_key=api_key, integration_name="greynoise-sampleapp-v1.0.0-beta"
)
api_client = GreyNoise(api_config)

for ip_address in ip_addresses:
    try:
        resp = api_client.ip(ip_address)
        if resp and resp["business_service_intelligence"]["found"]:
            print(resp)
            print("IP in RIOT Dataset")
        if resp and resp["internet_scanner_intelligence"]["found"]:
            print(resp)
            print("Noise Detected")
        if (
            not resp
            or not resp["business_service_intelligence"]["found"]
            or not resp["internet_scanner_intelligence"]["found"]
        ):
            print("No Noise Detected and not in RIOT Dataset")
    except Exception as e:
        print("An error occurred: ", e)
