#Python Imports
import os
import re
import socket
import strictyaml
import sys

from urllib.parse import urlparse
from ipwhois import IPWhois

# My Imports
from Modules import TitleOpen
from Modules import virusTotal
from Modules import whoIS
from Modules import hash
from Modules import dns

# Opening Config file
try:
    f = open('config.yaml','r')
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not Found")

def switchMenu(choice):
    if choice == '1':
        urlSanitise()
    if choice == '2':
        repChecker()
    if choice == '3':
        hashMenu()
    if choice == '4':
        dnsMenu()
    if choice == '0':
        sys.exit("Exiting safeWatch... done")
    else:
        mainMenu()

def mainMenu():
    print("\n --------------------------------- ")
    print("\n           s  a  f  e  W  a  t  c  h           ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: Sanitise URL ")
    print(" OPTION 2: Reputation Checker")
    print("OPTION 3: Hashing Menu")
    print("OPTION 4: Dns Tools")
    print(" OPTION 0: Exit Tool")
    switchMenu(input())

def titleLogo():
    TitleOpen.titleOpen()
    os.system('cls || clear')

#############################################################------1
def urlSanitise():
    print("\n --------------------------------- ")
    print(" U R L   S A N I T I S E   T O O L ")
    
    print(" --------------------------------- ")
    url = str(input("Enter URL to sanitize: ").strip())
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    print("\n" + x)
    mainMenu()
#############################################################

#############################################################------3
def repChecker():
    print("\n --------------------------------- ")
    print(" R E P U T A T I O N     C H E C K ")
    print(" --------------------------------- ")
    rawInput = input("Enter IP, URL ").split()
    ip = str(rawInput[0])

    s = re.findall(r'\S+@\S+', ip)    #checking that user input  is email or not
    if s:
        print(' Email Detected...')
        # Email analyzing function is yet to write
    else:
        if 'http' in ip:
            ip = socket.gethostbyname(get_domain(ip))
        whoIS.whoIsPrint(ip)
        wIP = socket.gethostbyname(ip)
    
    api =  configvars.data['VT_API_KEY']
    
    virusTotal.vt_report(api,wIP)
    mainMenu()
        


# def whoIsPrint(ip):
#     try:
#         w = IPWhois(ip)
#         w = w.lookup_whois()
#         addr = str(w['nets'][0]['address'])
#         addr = addr.replace('\n', ', ')
#         print("\n WHO IS REPORT:")
#         print("  CIDR:      " + str(w['nets'][0]['cidr']))
#         print("  Name:      " + str(w['nets'][0]['name']))
#         print("  Range:     " + str(w['nets'][0]['range']))
#         print("  Descr:     " + str(w['nets'][0]['description']))
#         print("  Country:   " + str(w['nets'][0]['country']))
#         print("  State:     " + str(w['nets'][0]['state']))
#         print("  City:      " + str(w['nets'][0]['city']))
#         print("  Address:   " + addr)
#         print("  Post Code: " + str(w['nets'][0]['postal_code']))
#         print("  Created:   " + str(w['nets'][0]['created']))
#         print("  Updated:   " + str(w['nets'][0]['updated']))
#     except:
#         print("\n  IP Not Found - Checking Domains")
#         ip = re.sub('https://', '', ip)
#         ip = re.sub('http://', '', ip)
#         try:
#             if c == 0:
#                 s = socket.gethostbyname(ip)
#                 print( '  Resolved Address: %s' % s)
#                 c = 1
#                 whoIsPrint(s)
#         except:
#             print(' IP or Domain not Found')


def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain


def hashSwitch(choice):
    if choice == 1:
        hash.hashFile()
    elif choice == 2:
        hash.hashText()
    elif choice == 3:
        virus_api =  configvars.data['VT_API_KEY']
        hValue = input("Provide Hash: ")
        hash.hashRating(hValue,virus_api)
    elif choice == 4:
        virus_api =  configvars.data['VT_API_KEY']
        hash.hashAndFileUpload(virus_api)


def hashMenu():
    print('-------------------------------------------------')
    print('*****************HASH MENU**********************')
    print('-------------------------------------------------')
    print('What Would You Like To Do : ')
    print('OPTION 1: Hash A File')
    print('OPTION 2: Input and Hash A Text')
    print('OPTION 3: Check A Hash For Unknown Malicious Activity')
    print('OPTION 4: Hash a File and Check For Unknown Malicious Activity')
    print('Option 0: Exit')
    hashSwitch(int(input()))


def dnsSwitch(choice):
    if choice == '1':
        dns.reverseDnsLookup()
    if choice == '2':
        dns.dnsLookup()
    if choice == '3':
        ip = input("Enter Ip: ")
        dns.whois(ip)

    else:
        mainMenu()

def dnsMenu():
    print("\n --------------------------------- ")
    print("         D N S    T O O L S        ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Reverse DNS Lookup")
    print(" OPTION 2: DNS Lookup")
    print(" OPTION 3: WHOIS Lookup")
    print(" OPTION 0: Exit to Main Menu")
    dnsSwitch(input())

if __name__ == '__main__':
    titleLogo()
    mainMenu()