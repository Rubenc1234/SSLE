import requests 
import time 
import random

DEVICE_ID = "sensor-001" 

def send_temp(): 
    while True: 
        temp = round(random.uniform(20.0, 30.0), 2) 
        payload = {"device_id": DEVICE_ID, "temperature": temp} 
        try: 
            requests.post("http://localhost:5001/ingest", json=payload) 
            print("Sent:", payload) 
        except Exception as e: 
            print("Error:", e) 
        time.sleep(5)
 
if __name__ == '__main__': 
    send_temp() 
