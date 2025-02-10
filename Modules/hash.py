import requests
import hashlib

def hashFile():
    # print("fdds")
    import tkinter
    import hashlib
    from tkinter import filedialog
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()

def hashText():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())
   

hash
def hashRating(hash_value,api_key):
    # hash_value = input("Provide Hash: ")
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            print("VirusTotal Report:")
            print("File Hash:", data.get("data", {}).get("id", "N/A"))
            print("Analysis Date:", data.get("data", {}).get("attributes", {}).get("last_analysis_date", "N/A"))
            print("Malicious Detections:", data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", "N/A"))
            print("Suspicious Detections:", data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", "N/A"))
            print("Undetected:", data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("undetected", "N/A"))
        else:
            print(f"Error: {response.status_code} - {response.json().get('error', {}).get('message', 'Unknown error')}")
    except Exception as e:
        print(f"An error occurred: {e}")


def hashAndFileUpload(api_key):
    import tkinter
    import hashlib
    from tkinter import filedialog
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    hash_value = hasher.hexdigest()
    root.destroy()
    hashRating(hash_value,api_key)    


def hashSwitch(choice):
    if choice == 1:
        hashFile()
    elif choice == 2:
        hashText()
    elif choice == 3:
        hashRating()
    elif choice == 4:
        hashAndFileUpload("45de683c7bb871e7978471af9959c3de9588ea863a6acdaeeb159475a7742722")

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
