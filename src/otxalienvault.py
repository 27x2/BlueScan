import requests
import readline

api_key=''

def check_ip_v4():
    url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/'
    ip = input("Enter ip: ")
    
    #malware section
    malware = url + ip + '/malware'
    response_malware = requests.get(str(malware))

    #geo section
    geo = url + ip + '/geo'
    response_geo = requests.get(str(geo))
    print(response_malware.json())
    #return response.json()

check_ip_v4()