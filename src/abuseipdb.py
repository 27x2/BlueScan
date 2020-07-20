import requests
import json


url = 'https://api.abuseipdb.com/api/v2/check'

def check_ip_abuseipdb(ip):
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': ''
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if response.status_code == 200:
        res = response.json()
        print("IP           : " + str(res['data']['ipAddress']))
        print("Total reports: " + str(res['data']['totalReports']))
        print("Abuse Score  : " + str(res['data']['abuseConfidenceScore'])+'/100')
        print("Country      : " + str(res['data']['countryCode']))
        print("Domain       : " + str(res['data']['domain']))
    else:
        print('Can not connect to AbuseIPDB')
        exit
