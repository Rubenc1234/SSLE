
from flask import Flask, request, jsonify
from datetime import datetime
import os
import threading
import time
import requests
import sqlite3

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
    "storage-service"
)

SERVICE_ID = os.environ.get(
    "SERVICE_ID",
    "storage-001"
)

SERVICE_URL = os.environ.get(
    "SERVICE_URL",
    "http://localhost:5002"
)

SERVICE_TYPE = os.environ.get(
    "SERVICE_TYPE",
    "storage"
)

COUNTRY = os.environ.get("COUNTRY", "pt")
REGION = os.environ.get("REGION", "aveiro")
DC = os.environ.get("DC", "dc1")
RACK = os.environ.get("RACK", "r01")
NODE = os.environ.get("NODE", "node1")

DB = os.environ.get(
    "DB_PATH",
    "./temp_data.db"
)

DB_DIR = os.path.dirname(os.path.abspath(DB))
os.makedirs(DB_DIR, exist_ok=True)

HEARTBEAT_INTERVAL = 5
REQUEST_TIMEOUT = 3

# Prevent concurrent registration attempts from the heartbeat
registration_lock = threading.Lock()

# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS temperatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                temperature REAL NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT
            )
        """)

        conn.commit()
    finally:
        conn.close()


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
            timeout=REQUEST_TIMEOUT
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
                timeout=REQUEST_TIMEOUT
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
            # Retry on the next iteration

        time.sleep(HEARTBEAT_INTERVAL)


# --------------------------------------------------
# STORE TEMPERATURE
# --------------------------------------------------

@app.route('/store', methods=['POST'])
def store():
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

    if device_id is None or temperature is None:
        return jsonify({
            "error": "Missing device_id or temperature"
        }), 400

    device_id = str(device_id).strip()

    if not device_id or len(device_id) > 128:
        return jsonify({
            "error": "Invalid device_id"
        }), 400

    try:
        temperature = float(temperature)

        if not (-50 <= temperature <= 100):
            return jsonify({
                "error": "Temperature out of allowed range"
            }), 400

    except (TypeError, ValueError):
        return jsonify({
            "error": "Invalid temperature"
        }), 400

    source_ip = str(data.get("source_ip") or "")[:64]
    conn = get_db()

    try:
        conn.execute(
            """
            INSERT INTO temperatures (device_id, temperature, source_ip)
            VALUES (?, ?, ?)
            """,
            (device_id, temperature, source_ip)
        )

        conn.commit()

    except sqlite3.Error as e:
        conn.rollback()
        print("Database error:", e)

        return jsonify({
            "error": "Could not store data"
        }), 500

    finally:
        conn.close()

    return jsonify({
        "status": "stored"
    }), 200


# --------------------------------------------------
# RETRIEVE TEMPERATURES
# --------------------------------------------------

@app.route('/temperatures', methods=['GET'])
def temperatures():
    limit_value = request.args.get("limit", default="1000")

    try:
        limit = int(limit_value)

        if limit < 1 or limit > 10000:
            raise ValueError

    except (TypeError, ValueError):
        return jsonify({
            "error": "limit must be an integer between 1 and 10000"
        }), 400

    conn = get_db()

    try:
        rows = conn.execute(
            """
            SELECT id, device_id, temperature, timestamp, source_ip
            FROM temperatures
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

        result = [dict(row) for row in rows]

    finally:
        conn.close()

    return jsonify(result), 200


# --------------------------------------------------
# TEMPERATURE STATISTICS
# --------------------------------------------------

@app.route('/average', methods=['GET'])
def average():
    conn = get_db()

    try:
        row = conn.execute(
            """
            SELECT AVG(temperature) AS average_temperature,
                   COUNT(*) AS samples
            FROM temperatures
            """
        ).fetchone()

    finally:
        conn.close()

    average_temperature = row["average_temperature"]

    return jsonify({
        "average_temperature": (
            round(average_temperature, 2)
            if average_temperature is not None
            else None
        ),
        "samples": row["samples"]
    }), 200


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route('/health', methods=['GET'])
def health():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()

        return jsonify({
            "status": "ok"
        }), 200

    except sqlite3.Error:
        return jsonify({
            "status": "error",
            "message": "Database unavailable"
        }), 503


# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == '__main__':
    init_db()

    heartbeat_thread = threading.Thread(
        target=heartbeat,
        daemon=True
    )
    heartbeat_thread.start()

    app.run(
        host="0.0.0.0",
        port=5002,
        threaded=True
    )
