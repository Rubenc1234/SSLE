
import requests
import sys
import time
import os
import uuid
import math

REGISTRY = os.environ.get("REGISTRY", "http://localhost:5050")
INGESTION = os.environ.get("INGESTION", "http://localhost:5001")
STORAGE = os.environ.get("STORAGE", "http://localhost:5002")
ANALYTICS = os.environ.get("ANALYTICS", "http://localhost:5003")

TIMEOUT = 5

results = []


# --------------------------------------------------
# TEST FRAMEWORK
# --------------------------------------------------

def check(name, condition, details=None):
    passed = bool(condition)

    results.append({
        "name": name,
        "passed": passed,
        "details": details
    })

    if passed:
        print(f"[PASS] {name}")
    else:
        print(f"[FAIL] {name}")

    if details is not None:
        print(f"       {details}")


def request(method, url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    return requests.request(method, url, **kwargs)


def safe_json(response):
    try:
        return response.json()
    except (ValueError, requests.exceptions.JSONDecodeError):
        return None


# --------------------------------------------------
# 1. REGISTRY
# --------------------------------------------------

def test_registry():

    print("\n--- 1. REGISTRY ---")

    try:
        response = request("GET", f"{REGISTRY}/services")

        check(
            "Registry is running",
            response.status_code == 200,
            f"HTTP {response.status_code}"
        )

        if response.status_code != 200:
            return

        services = safe_json(response)

        check(
            "Registry returns valid JSON",
            isinstance(services, dict)
        )

        if not isinstance(services, dict):
            return

        print("Registered services:")

        for service_id, service in services.items():
            print(f"  {service_id}: {service}")

        required_services = {
            "storage-service",
            "ingestion-service",
            "analytics-service"
        }

        registered_names = {
            service.get("name")
            for service in services.values()
            if isinstance(service, dict)
        }

        for service_name in required_services:
            check(
                f"Service registered: {service_name}",
                service_name in registered_names
            )

    except requests.RequestException as e:
        check("Registry is running", False, str(e))


# --------------------------------------------------
# 2. SERVICE DISCOVERY
# --------------------------------------------------

def test_discovery():

    print("\n--- 2. SERVICE DISCOVERY ---")

    try:
        response = request(
            "GET",
            f"{REGISTRY}/services/storage-service"
        )

        check(
            "Storage discovery",
            response.status_code == 200,
            f"HTTP {response.status_code}"
        )

        if response.status_code != 200:
            return

        data = safe_json(response)

        check(
            "Discovery returns valid JSON",
            isinstance(data, dict)
        )

        if not isinstance(data, dict):
            return

        storage_url = data.get("url")

        check(
            "Storage URL returned",
            isinstance(storage_url, str) and storage_url.startswith("http")
        )

        if storage_url:
            print("Storage discovered at:", storage_url)

            check(
                "Discovered Storage URL matches configured Storage",
                storage_url.rstrip("/") == STORAGE.rstrip("/")
            )

    except requests.RequestException as e:
        check("Storage discovery", False, str(e))


# --------------------------------------------------
# 3. INGESTION
# --------------------------------------------------

def test_ingestion():

    print("\n--- 3. INGESTION ---")

    device_id = f"integration-test-{uuid.uuid4().hex[:12]}"
    temperature = 25.5

    payload = {
        "device_id": device_id,
        "temperature": temperature
    }

    try:
        response = request(
            "POST",
            f"{INGESTION}/ingest",
            json=payload
        )

        check(
            "Ingestion accepts valid sensor data",
            response.status_code == 200,
            f"HTTP {response.status_code}"
        )

        data = safe_json(response)

        check(
            "Ingestion returns valid JSON",
            isinstance(data, dict)
        )

        if isinstance(data, dict):
            check(
                "Ingestion confirms successful processing",
                data.get("status") == "ingested"
            )

        # Guardar os dados para o teste de persistência
        return {
            "device_id": device_id,
            "temperature": temperature
        }

    except requests.RequestException as e:
        check("Ingestion accepts valid sensor data", False, str(e))
        return None


# --------------------------------------------------
# 4. STORAGE
# --------------------------------------------------

def test_storage(test_reading):

    print("\n--- 4. STORAGE ---")

    try:
        response = request(
            "GET",
            f"{STORAGE}/temperatures"
        )

        check(
            "Storage is accessible",
            response.status_code == 200,
            f"HTTP {response.status_code}"
        )

        if response.status_code != 200:
            return

        data = safe_json(response)

        check(
            "Storage returns valid JSON",
            isinstance(data, list)
        )

        if not isinstance(data, list):
            return

        check(
            "Storage contains temperature records",
            len(data) > 0
        )

        if test_reading is None:
            check(
                "New reading persisted",
                False,
                "Ingestion test did not produce a reading"
            )
            return

        matching_records = [
            item for item in data
            if isinstance(item, dict)
            and item.get("device_id") == test_reading["device_id"]
        ]

        check(
            "New reading persisted",
            len(matching_records) > 0
        )

        if matching_records:
            stored = matching_records[0]

            check(
                "Stored temperature matches submitted value",
                math.isclose(
                    float(stored.get("temperature")),
                    test_reading["temperature"],
                    rel_tol=0,
                    abs_tol=0.001
                )
            )

            print("Verified record:", stored)

    except (requests.RequestException, ValueError, TypeError) as e:
        check("Storage test", False, str(e))


# --------------------------------------------------
# 5. ANALYTICS
# --------------------------------------------------

def test_analytics():

    print("\n--- 5. ANALYTICS ---")

    try:
        response = request(
            "GET",
            f"{ANALYTICS}/average"
        )

        check(
            "Analytics is accessible",
            response.status_code == 200,
            f"HTTP {response.status_code}"
        )

        if response.status_code != 200:
            return

        data = safe_json(response)

        check(
            "Analytics returns valid JSON",
            isinstance(data, dict)
        )

        if not isinstance(data, dict):
            return

        average = data.get("average_temperature")

        valid_average = (
            isinstance(average, (int, float))
            and not isinstance(average, bool)
            and math.isfinite(average)
        )

        check(
            "Average temperature is numeric and finite",
            valid_average
        )

        if valid_average:
            print("Average temperature:", average)

    except (requests.RequestException, ValueError, TypeError) as e:
        check("Analytics test", False, str(e))


# --------------------------------------------------
# 6. INPUT VALIDATION
# --------------------------------------------------

def test_input_validation():

    print("\n--- 6. INPUT VALIDATION ---")

    invalid_payloads = [
        (
            "Missing device_id",
            {"temperature": 25.5}
        ),
        (
            "Missing temperature",
            {"device_id": "invalid-test"}
        ),
        (
            "Non-numeric temperature",
            {"device_id": "invalid-test", "temperature": "hot"}
        ),
        (
            "Temperature above allowed range",
            {"device_id": "invalid-test", "temperature": 999.9}
        ),
        (
            "Temperature below allowed range",
            {"device_id": "invalid-test", "temperature": -999.9}
        ),
        (
            "device_id exceeding maximum length",
            {"device_id": "x" * 200, "temperature": 25.5}
        )
    ]

    for name, payload in invalid_payloads:

        try:
            response = request(
                "POST",
                f"{INGESTION}/ingest",
                json=payload
            )

            check(
                f"Reject invalid input: {name}",
                response.status_code == 400,
                f"HTTP {response.status_code}"
            )

        except requests.RequestException as e:
            check(
                f"Reject invalid input: {name}",
                False,
                str(e)
            )


# --------------------------------------------------
# 7. SUMMARY
# --------------------------------------------------

def print_summary():

    print("\n" + "=" * 45)
    print("SSLE SYSTEM TEST SUMMARY")
    print("=" * 45)

    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed

    print(f"Total tests: {len(results)}")
    print(f"Passed:      {passed}")
    print(f"Failed:      {failed}")

    if failed:
        print("\nFailed tests:")

        for result in results:
            if not result["passed"]:
                print(f"  - {result['name']}")
                if result["details"]:
                    print(f"    {result['details']}")

    print("=" * 45)

    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")

    print("=" * 45 + "\n")

    return failed == 0


# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":

    print("\n=== SSLE SYSTEM INTEGRATION TEST ===")

    start_time = time.perf_counter()

    test_registry()
    test_discovery()

    test_reading = test_ingestion()
    test_storage(test_reading)

    test_analytics()
    test_input_validation()

    elapsed = time.perf_counter() - start_time

    print(f"\nExecution time: {elapsed:.3f} seconds")

    success = print_summary()

    sys.exit(0 if success else 1)
