#Python Imports
import os
import re
import socket
import strictyaml

from urllib.parse import urlparse
from ipwhois import IPWhois

# My Imports
from Modules import TitleOpen
from Modules import virusTotal


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
    # if choice == '2':
    #     decoderMenu()
    if choice == '2':
        repChecker()
    # if choice == '4':
    #     dnsMenu()
    # if choice == '5':
    #     hashMenu()
    # if choice == '6':
    #     phishingMenu()
    # if choice == '7':
    #     urlscanio()
    # if choice == '9':
    #     extrasMenu()
    # if choice == '0':
    #     sys.exit("Exiting Sooty... done")
    else:
        mainMenu()

def mainMenu():
    print("\n --------------------------------- ")
    print("\n           s  a  f  e  W  a  t  c  h           ")
    print("\n --------------------------------- ")
    print(" What would you like to do? ")
    print("\n OPTION 1: Sanitise URL For emails ")
    # print(" OPTION 3: Decoders (PP, URL, SafeLinks) ")
    print(" OPTION 2: Reputation Checker")
    # print(" OPTION 4: DNS Tools")
    # print(" OPTION 5: Hashing Function")
    # print(" OPTION 6: Phishing Analysis")
    # print(" OPTION 7: URL scan")
    # print(" OPTION 9: Extras")
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
        whoIsPrint(ip)
        wIP = socket.gethostbyname(ip)
    
    api =  configvars.data['VT_API_KEY']
    
    #Getting virus total Report
    virusTotal.vt_report(api,wIP)
        


def whoIsPrint(ip):
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
        # print("  Handle:    " + str(w['nets'][0]['handle']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
        # print("  Emails:    " + str(w['nets'][0]['emails']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))
    except:
        print("\n  IP Not Found - Checking Domains")
        ip = re.sub('https://', '', ip)
        ip = re.sub('http://', '', ip)
        try:
            if c == 0:
                s = socket.gethostbyname(ip)
                print( '  Resolved Address: %s' % s)
                c = 1
                whoIsPrint(s)
        except:
            print(' IP or Domain not Found')


def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain


if __name__ == '__main__':
    titleLogo()
    mainMenu()