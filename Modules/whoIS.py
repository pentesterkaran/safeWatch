from ipwhois import IPWhois
import re
from datetime import datetime,date
import os
import socket 

def whoIsPrint(ip):
    
    now = datetime.now()

    today = now.strftime("%m-%d-%Y")

    if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
    f= open('output/'+today+'/'+str(ip) + ".txt","a+")
    f.truncate(0)
    print("\n --------------------------------- ")
    print("\n WhoIS Report:")
    print("\n --------------------------------- \n")
    f.write("\n --------------------------------- ")
    f.write("\n WhoIS Report:")
    f.write("\n --------------------------------- \n")

    
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        # print("\n WHO IS REPORT:")
        print("  CIDR:      " + str(w['nets'][0]['cidr']))
        print("  Name:      " + str(w['nets'][0]['name']))
        print("  Range:     " + str(w['nets'][0]['range']))
        print("  Descr:     " + str(w['nets'][0]['description']))
        print("  Country:   " + str(w['nets'][0]['country']))
        print("  State:     " + str(w['nets'][0]['state']))
        print("  City:      " + str(w['nets'][0]['city']))
        print("  Address:   " + addr)
        print("  Post Code: " + str(w['nets'][0]['postal_code']))
        print("  Created:   " + str(w['nets'][0]['created']))
        print("  Updated:   " + str(w['nets'][0]['updated']))
        f.write("  \nCIDR:      " + str(w['nets'][0]['cidr']))
        f.write("  \nName:      " + str(w['nets'][0]['name']))
        f.write("  \nRange:     " + str(w['nets'][0]['range']))
        f.write("  \nDescr:     " + str(w['nets'][0]['description']))
        f.write("  \nCountry:   " + str(w['nets'][0]['country']))
        f.write("  \nState:     " + str(w['nets'][0]['state']))
        f.write("  \nCity:      " + str(w['nets'][0]['city']))
        f.write("  \nAddress:   " + addr)
        f.write("  \nPost Code: " + str(w['nets'][0]['postal_code']))
        f.write("  \nCreated:   " + str(w['nets'][0]['created']))
        f.write("  \nUpdated:   " + str(w['nets'][0]['updated']))
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
