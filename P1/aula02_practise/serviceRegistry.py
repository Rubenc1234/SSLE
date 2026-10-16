from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import random

app = Flask(__name__)

registry = {}

HEALTH_TIMEOUT = 15  # segundos

# -----------------------------------
# REGISTRATION / HEARTBEAT
# -----------------------------------

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    service_id = data.get("service_id")
    name = data.get("name") # guardar o nome do serviço
    url = data.get("url")

    if not service_id or not url:
        return jsonify({"error": "Missing service_id or url"}), 400

    registry[service_id] = {
        "name": name, # adicionar o atributo name
        "url": url,
        "last_seen": datetime.utcnow()
    }

    return jsonify({
        "message": "Service registered",
        "service_id": service_id
    }), 200


# Adicionar esta nova rota em falta
@app.route('/services', methods=['GET'])
def get_all_services():
    return jsonify(registry), 200


@app.route('/heartbeat', methods=['POST'])
def heartbeat():

    data = request.get_json()
    service_id = data.get("service_id")

    if service_id not in registry:
        return jsonify({"error": "Unknown service"}), 404

    registry[service_id]["last_seen"] = datetime.utcnow()

    return jsonify({
        "status": "alive"
    }), 200

# -----------------------------------
# DISCOVERY
# -----------------------------------

@app.route('/services/<service_name>', methods=['GET'])
def discover(service_name):

    now = datetime.utcnow()

    available = []

    for service_id, service in registry.items():

        if service["name"] != service_name:
            continue

        if now - service["last_seen"] < timedelta(seconds=HEALTH_TIMEOUT):
            available.append(service["url"])

    if not available:
        return jsonify({"error": "No healthy instances"}), 404

    # simples load balancing
    selected = random.choice(available)

    return jsonify({
        "url": selected
    }), 200

# -----------------------------------
# HEALTH CLEANUP
# -----------------------------------

def remove_dead_services():

    now = datetime.utcnow()

    dead = []

    for service_id, service in registry.items():

        if now - service["last_seen"] >= timedelta(seconds=HEALTH_TIMEOUT):
            dead.append(service_id)

    for service_id in dead:
        del registry[service_id]

if __name__ == '__main__':
    app.run(port=5050)
