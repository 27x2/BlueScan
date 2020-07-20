# -*- coding: utf8 -*-
from virustotal import *
from abuseipdb import *
from badip import *
from xforceibm import *
import argparse

def main():
    print(" ____   _               ___   ______        ___")
    print("|  _ \ | |             |__ \ |____  |      |__ \\")
    print("| |_) || | _   _   ___    ) |    / / __  __   ) |")
    print("|  _ < | || | | | / _ \  / /    / /  \ \/ /  / /")
    print("| |_) || || |_| ||  __/ / /_   / /    >  <  / /_")
    print("|____/ |_| \__,_| \___||____| /_/    /_/\_\|____|")
    print('\n')
    print('Use -h or --help')
    print('usage: BleuScan.py [-h] [-H HASH] [-i IP] [-d DOMAIN]')
    print('Scan hash, IP, virus online')
    parser = argparse.ArgumentParser(description='Scan hash, IP, virus online',
                                    epilog='Hope you like the program, for any feedback, please conntact me: binnhhuynhvanquoc@gmail.com')
    parser.add_argument('-H', '--hash', action='store',default=None, help='check your hash')
    parser.add_argument('-i', '--ip', action='store',default=None, help='check your IP')
    parser.add_argument('-d', '--domain', action='store',default=None, help='check your domain')
    args = parser.parse_args()
    if args.hash is not None:
        check_hash(args.hash)
    elif args.ip is not None:
        print("[+] Your IP: "+args.ip)
        print("|____Result:")
        print("-------[-] Virus total: ")
        check_ip(args.ip)
        print("|\n|\n-------[-] AbuseIPDB: ")
        check_ip_abuseipdb(args.ip)
        print("|\n|\n-------[-] BadIP: ")
        check_ip_badip(args.ip)
        print("|\n|\n-------[-] X-force IBM: ")
        check_ip_xforceibm(args.ip)
    elif args.domain is not None:
        check_domains(args.domain)
    else:
        return 0

if __name__ == "__main__":
    main()
