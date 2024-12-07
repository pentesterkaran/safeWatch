import requests
import os
from datetime import datetime,date

def vt_report(api,ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    # api = '2b2dcd1ac968067832546b789f36dd2721ea37771e98363dc553264901dad05a'

    headers = {
        'x-apikey':api
    }

    now = datetime.now()

    today = now.strftime("%m-%d-%Y")

    if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
    f= open('output/'+today+'/'+str(ip) + ".txt","a+")
    f.truncate(0)
    print("\n --------------------------------- ")
    print("\n VirusTotal Report:")
    print("\n --------------------------------- \n")
    f.write("\n --------------------------------- ")
    f.write("\n VirusTotal Report:")
    f.write("\n --------------------------------- \n")


    
    response = requests.get(url=url,headers=headers)
    # print(response.json())
    if response.status_code==200:
        result = response.json()
        for each in result:
            analysis_status = result['data']['attributes']['last_analysis_stats']
            # print("\nStatus Of Analysis-----")
            f.write("\nStatus Of Analysis-----")
            for i in analysis_status:
                print(f'\n{i} : {analysis_status[i]}')
                f.write(f'\n{i} : {analysis_status[i]}')
            analysis_result = result['data']['attributes']['last_analysis_results']
            print("\n\n")
            # print("Result of Analysis---------------\n")
            f.write("\n\nResult of Analysis---------------")
            # print("engineName\t\t\t\tCategory\t\t\t\tResult")
            f.write("\nengineName\t\t\t\tCategory\t\t\t\tResult")
            for i in analysis_result:
                # print("----------------------------------------------------------------------------------------------------------------------------------")
                # print(f"{i}\t\t\t\t\t{analysis_result[i]['category']}\t\t\t\t\t{analysis_result[i]['result']}" )
                f.write("\n------------------------------------------------------------------------------------------------------------------------------")
                f.write(f"\n{i}\t\t\t\t\t{analysis_result[i]['category']}\t\t\t\t\t{analysis_result[i]['result']}" )


    else:
         print(f"Virus Total request Failed with response code {response.status_code}")