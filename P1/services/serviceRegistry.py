
from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import threading
import time
import random

app = Flask(__name__)

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

HEALTH_TIMEOUT = 15  # seconds
CLEANUP_INTERVAL = 5  # seconds

registry = {}
registry_lock = threading.Lock()

# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Missing JSON body"
        }), 400

    service_id = data.get("service_id")
    name = data.get("name")
    url = data.get("url")

    if not service_id or not name or not url:
        return jsonify({
            "error": "Missing service_id, name or url"
        }), 400

    service = {
        "name": name,
        "url": url,
        "type": data.get("type"),
        "country": data.get("country"),
        "region": data.get("region"),
        "dc": data.get("dc"),
        "rack": data.get("rack"),
        "node": data.get("node"),
        "last_seen": datetime.now(timezone.utc).replace(tzinfo=None)
    }

    with registry_lock:
        registry[service_id] = service

    return jsonify({
        "message": "Service registered",
        "service_id": service_id
    }), 200


# --------------------------------------------------
# LIST SERVICES + FILTERS
# --------------------------------------------------

@app.route('/services', methods=['GET'])
def get_all_services():
    # Remove expired registrations before listing
    remove_dead_services()

    filters = request.args.to_dict()

    with registry_lock:
        result = {}

        for service_id, service in registry.items():
            matches = all(
                service.get(key) == value
                for key, value in filters.items()
            )

            if not matches:
                continue

            result[service_id] = {
                **service,
                "last_seen": service["last_seen"].isoformat()
            }

    return jsonify(result), 200


# --------------------------------------------------
# HEARTBEAT
# --------------------------------------------------

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Missing JSON body"
        }), 400

    service_id = data.get("service_id")

    with registry_lock:
        if service_id not in registry:
            return jsonify({
                "error": "Unknown service"
            }), 404

        registry[service_id]["last_seen"] = datetime.now(timezone.utc).replace(tzinfo=None)

    return jsonify({
        "status": "alive"
    }), 200


# --------------------------------------------------
# SERVICE DISCOVERY
# --------------------------------------------------

@app.route('/services/<service_name>', methods=['GET'])
def discover(service_name):
    # Remove expired registrations first
    remove_dead_services()

    filters = request.args.to_dict()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    with registry_lock:
        available = []

        for service_id, service in registry.items():
            if service["name"] != service_name:
                continue

            # Apply optional metadata filters
            if not all(
                service.get(key) == value
                for key, value in filters.items()
            ):
                continue

            # Only return healthy instances
            if now - service["last_seen"] < timedelta(
                seconds=HEALTH_TIMEOUT
            ):
                available.append({
                    "service_id": service_id,
                    "url": service["url"]
                })

        if not available:
            return jsonify({
                "error": "No healthy instances"
            }), 404

        selected = random.choice(available)

    return jsonify({
        "service_id": selected["service_id"],
        "url": selected["url"]
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
# REMOVE DEAD SERVICES
# --------------------------------------------------

def remove_dead_services():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(seconds=HEALTH_TIMEOUT)

    with registry_lock:
        dead = [
            service_id
            for service_id, service in registry.items()
            if service["last_seen"] <= cutoff
        ]

        for service_id in dead:
            del registry[service_id]

    if dead:
        print("Removed inactive services:", dead)


def cleanup_loop():
    while True:
        try:
            remove_dead_services()
        except Exception as e:
            print("Cleanup error:", e)

        time.sleep(CLEANUP_INTERVAL)


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == '__main__':
    cleanup_thread = threading.Thread(
        target=cleanup_loop,
        daemon=True
    )
    cleanup_thread.start()

    app.run(
        host="0.0.0.0",
        port=5050,
        threaded=True
    )
