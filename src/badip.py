import requests
import json
#import readline
from prettytable import PrettyTable
from termcolor import colored


def check_ip_badip(ip):

    url = 'https://www.badips.com/get/info/'
    check = url + ip
    response = requests.get(str(check))

    if response.status_code == 200:
        table_data = PrettyTable(['IP', 'DETECT'])
        if response.json()['Listed']:
            detect = colored("Yes","red")
        else:
            detect = colored("None","green")
        table_data.add_row([ip, detect])
        print(table_data)
    else:
        print('Can not connect to BadIP')
        exit
