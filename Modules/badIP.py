# www.badips.com is not working, i'll write this code again when website again starts





import requests
import os
from datetime import datetime,date

ip = '109.70.100.1'
now = datetime.now()
today = now.strftime("%m-%d-%Y")

if not os.path.exists('output/'+today):
    os.makedirs('output/'+today)
f= open('output/'+today+'/'+str(ip) + ".txt","a+")


print("\n Checking BadIP's... ")
f.write("\n\n ---------------------------------")
f.write("\n BadIP's Report : ")
f.write("\n --------------------------------- \n")


BAD_IPS_URL = 'https://www.badips.com/get/info/' + ip
try:
    response = requests.get(BAD_IPS_URL)
except:
    print("Unable to request")

if response.status_code == 200:
    result = response.json()
    print("  " + str(result['suc']))
    print("  Total Reports : " + str(result['ReporterCount']['sum']))
    print("\n  IP has been reported in the following Categories:")
    f.write("  " + str(result['suc']))
    f.write("\n  Total Reports : " + str(result['ReporterCount']['sum']))
    f.write("\n  IP has been reported in the following Categories:")
    for each in result['LastReport']:
        timeReport = datetime.fromtimestamp(result['LastReport'].get(each))
        print('   - ' + each + ': ' + str(timeReport))
        f.write('\n   - ' + each + ': ' + str(timeReport))
else:
    print('  Error reaching BadIPs')