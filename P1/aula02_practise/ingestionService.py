from flask import Flask, request, jsonify
import requests
import threading
import time

app = Flask(__name__)

REGISTRY_URL = "http://localhost:5050"

SERVICE_NAME = "ingestion-service"
SERVICE_ID = "ingestion-001"
SERVICE_URL = "http://localhost:5001"

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
# INGEST
# --------------------------------------------------

@app.route('/ingest', methods=['POST'])
def ingest():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Missing JSON body"
        }), 400

    device_id = data.get("device_id")
    temperature = data.get("temperature")

    # Basic validation
    if device_id is None or temperature is None:
        return jsonify({
            "error": "Missing device_id or temperature"
        }), 400

    # Normalization
    try:
        temperature = float(temperature)
    except (TypeError, ValueError):

        return jsonify({
            "error": "Invalid temperature"
        }), 400

    payload = {
        "device_id": str(device_id),
        "temperature": temperature
    }

    # Discover Storage dynamically
    try:

        storage_url = discover_storage()

        response = requests.post(
            f"{storage_url}/store",
            json=payload,
            timeout=5
        )

        if response.status_code != 200:
            return jsonify({
                "error": "Storage failed"
            }), 502

    except Exception as e:

        return jsonify({
            "error": str(e)
        }), 503

    return jsonify({
        "status": "ingested"
    }), 200

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
    app.run(port=5001)
