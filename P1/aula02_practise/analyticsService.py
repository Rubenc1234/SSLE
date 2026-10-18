
from flask import Flask, jsonify
import os
import requests
import threading
import time

app = Flask(__name__)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

REGISTRY_URL = os.environ.get(
    "REGISTRY_URL",
    "http://localhost:5050"
).rstrip("/")

SERVICE_NAME = os.environ.get(
    "SERVICE_NAME",
    "analytics-service"
)

SERVICE_ID = os.environ.get(
    "SERVICE_ID",
    "analytics-001"
)

SERVICE_URL = os.environ.get(
    "SERVICE_URL",
    "http://localhost:5003"
)

SERVICE_TYPE = os.environ.get(
    "SERVICE_TYPE",
    "analytics"
)

COUNTRY = os.environ.get("COUNTRY", "pt")
REGION = os.environ.get("REGION", "aveiro")
DC = os.environ.get("DC", "dc1")
RACK = os.environ.get("RACK", "r01")
NODE = os.environ.get("NODE", "node1")

REQUEST_TIMEOUT = 5
REGISTRY_TIMEOUT = 3
HEARTBEAT_INTERVAL = 5

# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

registration_lock = threading.Lock()


def register():
    payload = {
        "service_id": SERVICE_ID,
        "name": SERVICE_NAME,
        "url": SERVICE_URL,
        "type": SERVICE_TYPE,
        "country": COUNTRY,
        "region": REGION,
        "dc": DC,
        "rack": RACK,
        "node": NODE
    }

    try:
        response = requests.post(
            f"{REGISTRY_URL}/register",
            json=payload,
            timeout=REGISTRY_TIMEOUT
        )

        response.raise_for_status()

        print("Registry registration successful:", response.json())
        return True

    except requests.RequestException as e:
        print("Registration error:", e)
        return False


# --------------------------------------------------
# HEARTBEAT AND REGISTRATION RETRY
# --------------------------------------------------

def heartbeat():
    registered = False

    while True:
        try:
            if not registered:
                with registration_lock:
                    registered = register()

                if not registered:
                    time.sleep(HEARTBEAT_INTERVAL)
                    continue

            response = requests.post(
                f"{REGISTRY_URL}/heartbeat",
                json={"service_id": SERVICE_ID},
                timeout=REGISTRY_TIMEOUT
            )

            if response.status_code == 404:
                print("Registry lost this service. Re-registering...")

                with registration_lock:
                    registered = register()

            elif response.ok:
                registered = True

            else:
                print(
                    "Heartbeat failed:",
                    response.status_code,
                    response.text
                )

        except requests.RequestException as e:
            print("Heartbeat error:", e)

        time.sleep(HEARTBEAT_INTERVAL)


# --------------------------------------------------
# STORAGE DISCOVERY
# --------------------------------------------------

def discover_storage():
    response = requests.get(
        f"{REGISTRY_URL}/services/storage-service",
        timeout=REGISTRY_TIMEOUT
    )

    response.raise_for_status()

    storage_url = response.json().get("url")

    if not storage_url:
        raise RuntimeError("Registry returned no Storage URL")

    return storage_url.rstrip("/")


# --------------------------------------------------
# AVERAGE TEMPERATURE
# --------------------------------------------------

@app.route('/average', methods=['GET'])
def average_temperature():
    try:
        storage_url = discover_storage()

        response = requests.get(
            f"{storage_url}/average",
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:
            return jsonify({
                "error": "Could not retrieve storage statistics",
                "storage_status": response.status_code
            }), 502

        data = response.json()

        return jsonify({
            "average_temperature": data.get(
                "average_temperature"
            ),
            "samples": data.get("samples", 0)
        }), 200

    except requests.RequestException as e:
        return jsonify({
            "error": "Storage service unavailable",
            "details": str(e)
        }), 503

    except (ValueError, RuntimeError) as e:
        return jsonify({
            "error": str(e)
        }), 503


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok"
    }), 200


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == '__main__':
    heartbeat_thread = threading.Thread(
        target=heartbeat,
        daemon=True
    )
    heartbeat_thread.start()

    app.run(
        host="0.0.0.0",
        port=5003,
        threaded=True
    )
