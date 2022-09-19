from greynoise import GreyNoise

api_key = '<enter-api-key-here>'
ip_addresses = ['108.168.3.151', '8.8.8.8', '318.1.1.1']
api_client = GreyNoise(api_key=api_key, integration_name="greynoise-sampleapp-v1.0.0-beta")
for ip_address in ip_addresses:
    try:
        riot_resp = api_client.riot(ip_address)
        if riot_resp and riot_resp['riot']:
            print(riot_resp)
            print('IP in RIOT Dataset')
        else:
            ip_resp = api_client.quick(ip_address)
            if ip_resp and ip_resp[0]['noise']:
                print(ip_resp)
                print('Noise Detected')
            else:
                print('No Noise Detected')
    except Exception as e:
        print(e)
