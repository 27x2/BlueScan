import requests
import json
# import readline
from prettytable import PrettyTable
from termcolor import colored
api_key=''
api_password=''

def check_ip_xforceibm(ip):
    url = 'https://exchange.xforce.ibmcloud.com/api/ipr/'
    check = url+ip
    headers = {'Accept': 'application/json'}

    auth = {'API_KEY': 'c35175e4-8953-4f10-af3d-d8cc6438f791'}
    response = requests.get(str(check), headers=headers, auth=(api_key, api_password))
    if response.status_code == 200:
        print("RISK Score: "+str(response.json()["score"])+"/10")
