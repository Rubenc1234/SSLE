
from flask import Flask, request, jsonify
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
    "ingestion-service"
)

SERVICE_ID = os.environ.get(
    "SERVICE_ID",
    "ingestion-001"
)

SERVICE_URL = os.environ.get(
    "SERVICE_URL",
    "http://localhost:5001"
)

SERVICE_TYPE = os.environ.get(
    "SERVICE_TYPE",
    "ingestion"
)

COUNTRY = os.environ.get("COUNTRY", "pt")
REGION = os.environ.get("REGION", "aveiro")
DC = os.environ.get("DC", "dc1")
RACK = os.environ.get("RACK", "r01")
NODE = os.environ.get("NODE", "node1")

REQUEST_TIMEOUT = 5
DISCOVERY_TIMEOUT = 3
HEARTBEAT_INTERVAL = 5
DISCOVERY_CACHE_TTL = 10

# Storage discovery cache
_storage_url = None
_storage_url_time = 0.0
_storage_cache_lock = threading.Lock()

# Prevent concurrent registration attempts
registration_lock = threading.Lock()


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

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
            timeout=DISCOVERY_TIMEOUT
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
                timeout=DISCOVERY_TIMEOUT
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

def invalidate_storage_cache():
    global _storage_url, _storage_url_time
    with _storage_cache_lock:
        _storage_url = None
        _storage_url_time = 0.0

def discover_storage():
    global _storage_url, _storage_url_time

    now = time.monotonic()

    # Return cached URL while it is still valid
    with _storage_cache_lock:
        if (
            _storage_url
            and now - _storage_url_time < DISCOVERY_CACHE_TTL
        ):
            return _storage_url

        # Save the previous URL as a fallback
        cached_url = _storage_url

    try:
        response = requests.get(
            f"{REGISTRY_URL}/services/storage-service",
            timeout=DISCOVERY_TIMEOUT
        )

        response.raise_for_status()
        storage_url = response.json().get("url")

        if not storage_url:
            raise ValueError("Registry returned no Storage URL")

        storage_url = storage_url.rstrip("/")

        with _storage_cache_lock:
            _storage_url = storage_url
            _storage_url_time = time.monotonic()

        return storage_url

    except (requests.RequestException, ValueError, TypeError) as e:
        print("Storage discovery error:", e)

        if cached_url:
            print("Using last known Storage URL:", cached_url)
            return cached_url

        raise RuntimeError(
            "Storage service unavailable and no cached URL exists"
        ) from e


# --------------------------------------------------
# INGEST
# --------------------------------------------------

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Missing JSON body"
        }), 400
    if not isinstance(data, dict):
        return jsonify({
            "error": "JSON body must be an object"
        }), 400

    device_id = data.get("device_id")
    temperature = data.get("temperature")

    # Validate required fields
    if device_id is None or temperature is None:
        return jsonify({
            "error": "Missing device_id or temperature"
        }), 400

    # Validate device ID
    device_id = str(device_id).strip()

    if not device_id or len(device_id) > 128:
        return jsonify({
            "error": "Invalid device_id"
        }), 400

    # Normalize and validate temperature
    try:
        temperature = float(temperature)

    except (TypeError, ValueError):
        return jsonify({
            "error": "Invalid temperature"
        }), 400

    # Reject NaN and infinity
    if not (-50 <= temperature <= 100):
        return jsonify({
            "error": "Temperature must be between -50 and 100"
        }), 400

    payload = {
        "device_id": device_id,
        "temperature": temperature,
        "source_ip": request.remote_addr
    }

    # Discover Storage and forward the data
    try:
        storage_url = discover_storage()

        response = requests.post(
            f"{storage_url}/store",
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        # Se for erro do servidor (>= 500), invalidamos a cache para forçar novo discovery
        if response.status_code >= 500:
            invalidate_storage_cache()
            return jsonify({
                "error": "Storage server error",
                "storage_status": response.status_code
            }), 502

        if response.status_code != 200:
            return jsonify({
                "error": "Storage failed",
                "storage_status": response.status_code
            }), 502

    except (requests.RequestException, RuntimeError) as e:
        # Se houver falha de rede/exceção, invalidamos a cache imediatamente
        invalidate_storage_cache()
        return jsonify({
            "error": str(e)
        }), 503

    return jsonify({
        "status": "ingested"
    }), 200


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
        port=5001,
        threaded=True
    )
