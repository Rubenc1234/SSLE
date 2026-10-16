from flask import Flask, jsonify
import requests
import threading
import time

app = Flask(__name__)

REGISTRY_URL = "http://localhost:5050"

SERVICE_NAME = "analytics-service"
SERVICE_ID = "analytics-001"
SERVICE_URL = "http://localhost:5003"

# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

def register():

    try:
        response = requests.post(
            f"{REGISTRY_URL}/register",
            json={
                "service_id": SERVICE_ID,
                "name": SERVICE_NAME,
                "url": SERVICE_URL
            }
        )

        print("Registry:", response.json())

    except Exception as e:
        print("Registration error:", e)

# --------------------------------------------------
# HEARTBEAT
# --------------------------------------------------

def heartbeat():

    while True:

        try:
            requests.post(
                f"{REGISTRY_URL}/heartbeat",
                json={
                    "service_id": SERVICE_ID
                }
            )

        except Exception as e:
            print("Heartbeat error:", e)

        time.sleep(5)

# --------------------------------------------------
# STORAGE DISCOVERY
# --------------------------------------------------

def discover_storage():

    response = requests.get(
        f"{REGISTRY_URL}/services/storage-service"
    )

    if response.status_code != 200:
        raise Exception("Storage service unavailable")

    return response.json()["url"]

# --------------------------------------------------
# AVERAGE TEMPERATURE
# --------------------------------------------------

@app.route('/average', methods=['GET'])
def average_temperature():

    try:

        storage_url = discover_storage()

        response = requests.get(
            f"{storage_url}/temperatures",
            timeout=5
        )

        if response.status_code != 200:
            return jsonify({
                "error": "Could not retrieve data"
            }), 502

        data = response.json()

        if not data:
            return jsonify({
                "average_temperature": None
            }), 200

        temperatures = [
            item["temperature"]
            for item in data
        ]

        average = sum(temperatures) / len(temperatures)

        return jsonify({
            "average_temperature": round(average, 2),
            "samples": len(temperatures)
        }), 200

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 503

# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == '__main__':
    register()
    heartbeat_thread = threading.Thread(
        target=heartbeat,
        daemon=True
    )
    heartbeat_thread.start()
    app.run(port=5003)
