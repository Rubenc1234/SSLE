
"""
Prometheus metrics for the SSLE Threat Detection project.

Contains:
- Generic RED metrics (Rate, Errors, Duration)
- Branch A: DoS / payload monitoring
- Branch B: Integrity / fake sensor monitoring
- Branch C: Registry authenticity / hijacking monitoring

IMPORTANT:
Never use device_id, source_ip, or interpolated URLs as metric labels.
"""

from prometheus_client import Counter, Gauge, Histogram


# ============================================================
# GENERIC METRICS — RED (Rate, Errors, Duration)
# ============================================================

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total number of HTTP requests received",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        1.0,
        2.5,
        5.0,
        10.0,
    ),
)


# ============================================================
# BRANCH A — AVAILABILITY / DoS
# ============================================================

REQUEST_BODY_SIZE_BYTES = Histogram(
    "request_body_size_bytes",
    "HTTP request body size in bytes",
    buckets=(
        100,
        500,
        1000,
        5000,
        10000,
        50000,
        100000,
        500000,
        1000000,
        5000000,
    ),
)


# ============================================================
# BRANCH B — INTEGRITY / FAKE SENSORS
# ============================================================

REGISTRY_REGISTRATIONS_TOTAL = Counter(
    "registry_registrations_total",
    "Total number of service registrations in the Registry",
    ["name"],
)

STORAGE_UNIQUE_DEVICES_TOTAL = Gauge(
    "storage_unique_devices_total",
    "Number of distinct device IDs observed by the Storage",
)


# ============================================================
# BRANCH C — AUTHENTICITY / REGISTRY HIJACKING
# ============================================================

REGISTRY_OVERWRITES_TOTAL = Counter(
    "registry_overwrites_total",
    "Total number of overwrites of existing service IDs",
)

REGISTRY_ENTRIES_PER_NAME = Gauge(
    "registry_entries_per_name",
    "Number of Registry entries grouped by service name",
    ["name"],
)


# ============================================================
# OPTIONAL / LOW PRIORITY METRICS
# ============================================================

REGISTRY_DISCOVERY_REQUESTS_TOTAL = Counter(
    "registry_discovery_requests_total",
    "Total number of service discovery requests",
)

REGISTRY_REGISTRATION_REJECTED_TOTAL = Counter(
    "registry_registration_rejected_total",
    "Total number of rejected service registrations",
)


# ============================================================
# HELPER FUNCTIONS — BRANCH B
# ============================================================

def increment_registry_registration(name: str) -> None:
    """
    Increment the registration counter for a service name.

    Expected names in the current architecture:
    registry, storage, ingestion, analytics, sensor.
    """
    REGISTRY_REGISTRATIONS_TOTAL.labels(name=name).inc()


# ============================================================
# HELPER FUNCTIONS — BRANCH C
# ============================================================

def increment_registry_overwrite() -> None:
    """
    Increment only when an existing service_id is overwritten.
    """
    REGISTRY_OVERWRITES_TOTAL.inc()


def update_registry_entries_per_name(counts: dict[str, int]) -> None:
    """
    Update the number of Registry entries for each service name.
    Names that are no longer present are explicitly set to zero.
    """
    known_names = {
        "storage-service",
        "ingestion-service",
        "analytics-service",
        "sensor",
    }

    for name in known_names:
        REGISTRY_ENTRIES_PER_NAME.labels(name=name).set(
            counts.get(name, 0)
        )


# ============================================================
# HELPER FUNCTIONS — BRANCH B / STORAGE
# ============================================================

def set_storage_unique_devices(count: int) -> None:
    """
    Update the total number of distinct device IDs stored/observed.
    """
    STORAGE_UNIQUE_DEVICES_TOTAL.set(count)


# ============================================================
# HELPER FUNCTIONS — OPTIONAL METRICS
# ============================================================

def increment_registry_discovery() -> None:
    """
    Increment the Registry discovery request counter.
    """
    REGISTRY_DISCOVERY_REQUESTS_TOTAL.inc()


def increment_registry_registration_rejected() -> None:
    """
    Increment when a registration is rejected by Registry validation.
    """
    REGISTRY_REGISTRATION_REJECTED_TOTAL.inc()
