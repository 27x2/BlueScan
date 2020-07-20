# -*- coding: utf8 -*-
import requests
import json
#import readline
from prettytable import PrettyTable
from termcolor import colored
api_key=''

def check_domains(domain):

    url = 'https://www.virustotal.com/api/v3/domains/'
    check = url + domain
    header = {'x-apikey': api_key
            ,'Accept': 'application/json'}
    response = requests.get(str(check), headers=header)

    if response.status_code == 200:
        js = response.json()['data']['attributes']['last_analysis_results']

        table_data = PrettyTable(['VENDOR', 'CATEGORY', 'METHOD', 'RESULT'])
        harmful = 0
        count = 0
        for result in js:
            #change color
            scan_result='clean'
            if js[result]['result'] == "unrated":
                scan_result = colored(js[result]["result"],"grey")
            elif js[result]['result'] == "clean":
                scan_result = colored(js[result]["result"],"green")
            else:
                scan_result = colored(js[result]["result"],"red")
                harmful +=1

            #change color
            category=''
            if js[result]['category']=="undetected":
                category = colored(js[result]["category"],"grey")
            elif js[result]['category']=="harmless":
                category = colored(js[result]["category"],"white")
            else:
                category = colored(js[result]["category"],"red")
            if js[result]['method']:
                method = js[result]["method"]
            table_data.add_row([result, category, method,scan_result])
            count +=1
        print(table_data)
        print("\n===>Detected: "+str(harmful)+"/"+str(count))
    else:
        print('Can not connect to Virus total')
        exit
    

def check_ip(ip):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/'

    check = url + ip
    header = {'x-apikey': api_key
            ,'Accept': 'application/json'}
    response = requests.get(str(check), headers=header)
    if response.status_code == 200:
        js = response.json()['data']['attributes']['last_analysis_results']
        table_data = PrettyTable(['VENDOR', 'CATEGORY', 'METHOD', 'RESULT'])
        harmful = 0
        count = 0
        for result in js:
            #change color
            scan_result='clean'
            if js[result]['result'] == "unrated":
                scan_result = colored(js[result]["result"],"grey")
            elif js[result]['result'] == "clean":
                scan_result = colored(js[result]["result"],"green")
            else:
                scan_result = colored(js[result]["result"],"red")
                harmful +=1

            #change color 
            category=''
            if js[result]['category']=="undetected":
                category = colored(js[result]["category"],"grey")
            elif js[result]['category']=="harmless":
                category = colored(js[result]["category"],"white")
            else:
                category = colored(js[result]["category"],"red")
            if js[result]['method']:
                method = js[result]["method"]
            table_data.add_row([result, category, method,scan_result])
            count +=1
        print(table_data)
        print("\n===>Detected: "+str(harmful)+"/"+str(count))
    else:
        print('Can not connect to Virus total')
        exit

#check_ip('219.148.39.134')
#check_domains("google.com")

def check_hash(hash):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    #domain = input("Enter domain: ")
    #check = url + hash
    params = {'apikey': api_key,'resource': hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        res = response.json()
        if(res['response_code'])==0:
            exit()
        #js = res['scans']
        print(res)
        with open('test', "w+") as outfile:
            outfile.write(response  .text)
            outfile.close()
        table_data = PrettyTable(['VENDOR', 'DETECT', 'RESULT'])
        harmful = 0
        count = 0
        for result in js:
            #print(js[result]['detected'])
            if js[result]['detected']:
                detect = colored(js[result]["detected"],"red")
                harmful +=1
            else:
                detect = colored(js[result]["detected"],"white")
            
            if js[result]['result'] != None:
                scan_result = colored(js[result]["result"],"red")
            else:
                scan_result = colored(js[result]["result"],"white")
        
            table_data.add_row([result, detect,scan_result])
            count+=1
        print("[*] Your hash: "+hash)
        print("[*] Details: ")
        print("---[+] MD5: "+res["md5"])
        print("---[+] sha1: "+res["sha1"])
        print("---[+] sha256: "+res["sha256"]+"\n")

        print(table_data)
        print("\n===>Detected: "+str(harmful)+"/"+str(count))
    else:
        print('Can not connect to Virus total')
        exit
#check_hash('2914ca4ebf07c42fcd4f2b28bc72d0cd')
#check_hash('962ce6ed6729ab481d57a8cfbf65d40c')