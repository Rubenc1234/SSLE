import requests
import sys
import time


REGISTRY = "http://localhost:5050"
INGESTION = "http://localhost:5001"
STORAGE = "http://localhost:5002"
ANALYTICS = "http://localhost:5003"


def check(name, condition):
    if condition:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")
        sys.exit(1)


# --------------------------------------------------
# 1. Registry
# --------------------------------------------------

def test_registry():

    response = requests.get(
        f"{REGISTRY}/services"
    )

    check(
        "Registry is running",
        response.status_code == 200
    )

    services = response.json()

    print("Registered services:")
    for service_id, service in services.items():
        print(f"  {service_id}: {service}")


# --------------------------------------------------
# 2. Service discovery
# --------------------------------------------------

def test_discovery():

    response = requests.get(
        f"{REGISTRY}/services/storage-service"
    )

    check(
        "Storage discovery",
        response.status_code == 200
    )

    data = response.json()

    check(
        "Storage URL returned",
        "url" in data
    )

    print("Storage discovered at:", data["url"])


# --------------------------------------------------
# 3. Ingestion
# --------------------------------------------------

def test_ingestion():

    payload = {
        "device_id": "test-sensor",
        "temperature": 25.5
    }

    response = requests.post(
        f"{INGESTION}/ingest",
        json=payload
    )

    check(
        "Ingestion accepts sensor data",
        response.status_code == 200
    )

    print("Ingestion response:", response.json())


# --------------------------------------------------
# 4. Storage
# --------------------------------------------------

def test_storage():

    response = requests.get(
        f"{STORAGE}/temperatures"
    )

    check(
        "Storage returns data",
        response.status_code == 200
    )

    data = response.json()

    check(
        "Stored data is not empty",
        len(data) > 0
    )

    print("Stored data:")
    for item in data:
        print(" ", item)


# --------------------------------------------------
# 5. Analytics
# --------------------------------------------------

def test_analytics():

    response = requests.get(
        f"{ANALYTICS}/average"
    )

    check(
        "Analytics is working",
        response.status_code == 200
    )

    data = response.json()

    check(
        "Average temperature exists",
        "average_temperature" in data
    )

    print(
        "Average temperature:",
        data["average_temperature"]
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":

    print("\n=== SSLE SYSTEM TEST ===\n")

    try:
        test_registry()
        test_discovery()
        test_ingestion()
        test_storage()
        test_analytics()

        print("\n========================")
        print("ALL TESTS PASSED")
        print("========================\n")

    except requests.exceptions.ConnectionError as e:

        print("\n[ERROR] Could not connect to a service.")
        print("Make sure Registry, Storage, Ingestion and Analytics are running.")
        print(e)

        sys.exit(1)
