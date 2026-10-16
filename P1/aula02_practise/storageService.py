from flask import Flask, request, jsonify
import sqlite3
import requests
import threading
import time

app = Flask(__name__)

DB = "temp_data.db"

REGISTRY_URL = "http://localhost:5050"

SERVICE_NAME = "storage-service"
SERVICE_ID = "storage-001"
SERVICE_URL = "http://localhost:5002"

# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():

    conn = sqlite3.connect(DB)

    conn.row_factory = sqlite3.Row

    return conn

def init_db():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS temperatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            temperature REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

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
# STORE
# --------------------------------------------------

@app.route('/store', methods=['POST'])
def store():

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Missing JSON body"
        }), 400

    device_id = data.get("device_id")
    temperature = data.get("temperature")

    if device_id is None or temperature is None:
        return jsonify({
            "error": "Missing fields"
        }), 400

    try:

        temperature = float(temperature)

    except (TypeError, ValueError):

        return jsonify({
            "error": "Invalid temperature"
        }), 400

    conn = get_db()

    try:

        conn.execute(
            """
            INSERT INTO temperatures
            (device_id, temperature)
            VALUES (?, ?)
            """,
            (str(device_id), temperature)
        )

        conn.commit()

    except Exception as e:

        conn.rollback()

        return jsonify({
            "error": "Could not store data"
        }), 500

    finally:

        conn.close()

    return jsonify({
        "status": "stored"
    }), 200

# --------------------------------------------------
# RETRIEVAL
# --------------------------------------------------

@app.route('/temperatures', methods=['GET'])
def temperatures():

    conn = get_db()

    rows = conn.execute(
        """
        SELECT id, device_id, temperature, timestamp
        FROM temperatures
        ORDER BY timestamp DESC
        """
    ).fetchall()

    conn.close()

    result = [dict(row) for row in rows]

    return jsonify(result), 200

# --------------------------------------------------
# START
# --------------------------------------------------

if __name__ == '__main__':
    init_db()
    register()
    heartbeat_thread = threading.Thread(
        target=heartbeat,
        daemon=True
    )
    heartbeat_thread.start()
    app.run(port=5002)
