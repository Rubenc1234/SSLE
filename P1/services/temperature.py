
import os
import time
import random
import threading
import requests


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

REGISTRY_URL = os.environ.get(
    "REGISTRY_URL",
    "http://localhost:5050"
).rstrip("/")

DEVICE_ID = os.environ.get(
    "DEVICE_ID",
    "sensor-pt-aveiro-dc1-r01-n01"
)

SENSOR_INTERVAL = float(
    os.environ.get("SENSOR_INTERVAL", "5")
)

SERVICE_TYPE = "sensor"

COUNTRY = os.environ.get("COUNTRY", "pt")
REGION = os.environ.get("REGION", "aveiro")
DC = os.environ.get("DC", "dc1")
RACK = os.environ.get("RACK", "r01")
NODE = os.environ.get("NODE", "node1")

REGISTRY_TIMEOUT = 3
INGESTION_TIMEOUT = 5

HEARTBEAT_INTERVAL = 5
DISCOVERY_CACHE_TTL = 10

MIN_TEMPERATURE = 20.0
MAX_TEMPERATURE = 30.0


# Cache do endereço do Ingestion
cached_ingestion_url = None
last_discovery_time = 0


# --------------------------------------------------
# REGISTRATION AND HEARTBEAT
# --------------------------------------------------

def register():
    """
    Regista o sensor no Registry com os seus metadados.
    O sensor não disponibiliza um servidor HTTP próprio.
    """
    payload = {
        "service_id": DEVICE_ID,
        "name": "sensor",
        "url": "none",
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

        print("Sensor registado no Registry:", DEVICE_ID)
        return True

    except requests.RequestException as e:
        print("Erro no registo do sensor:", e)
        return False


def heartbeat():
    """
    Mantém o registo do sensor ativo.
    Se o Registry deixar de reconhecer o sensor,
    tenta registá-lo novamente.
    """
    registered = False

    while True:
        try:
            if not registered:
                registered = register()

                if not registered:
                    time.sleep(HEARTBEAT_INTERVAL)
                    continue

            response = requests.post(
                f"{REGISTRY_URL}/heartbeat",
                json={"service_id": DEVICE_ID},
                timeout=REGISTRY_TIMEOUT
            )

            if response.status_code == 404:
                print(
                    "Registry perdeu o sensor. "
                    "A registar novamente..."
                )
                registered = register()

            elif not response.ok:
                print(
                    "Heartbeat falhou:",
                    response.status_code,
                    response.text
                )

        except requests.RequestException as e:
            print("Erro no heartbeat:", e)

        time.sleep(HEARTBEAT_INTERVAL)


# --------------------------------------------------
# INGESTION DISCOVERY
# --------------------------------------------------

def discover_ingestion():
    """
    Descobre o Ingestion através do Registry.
    Guarda o último URL conhecido para tolerar
    falhas temporárias do Registry.
    """
    global cached_ingestion_url, last_discovery_time

    now = time.monotonic()

    if (
        cached_ingestion_url
        and now - last_discovery_time < DISCOVERY_CACHE_TTL
    ):
        return cached_ingestion_url

    try:
        response = requests.get(
            f"{REGISTRY_URL}/services/ingestion-service",
            timeout=REGISTRY_TIMEOUT
        )
        response.raise_for_status()

        ingestion_url = response.json().get("url")

        if not ingestion_url:
            raise RuntimeError(
                "Registry não devolveu o URL do Ingestion"
            )

        cached_ingestion_url = ingestion_url.rstrip("/")
        last_discovery_time = time.monotonic()

        return cached_ingestion_url

    except (
        requests.RequestException,
        ValueError,
        RuntimeError
    ) as e:
        print("Erro ao descobrir Ingestion:", e)

        if cached_ingestion_url:
            print("A utilizar o último URL conhecido.")
            return cached_ingestion_url

        last_discovery_time = 0

        raise RuntimeError(
            "Não foi possível descobrir o Ingestion"
        ) from e


# --------------------------------------------------
# TEMPERATURE GENERATION
# --------------------------------------------------

def read_temperature():
    """
    Simula uma leitura do sensor.
    Substituir por uma leitura de hardware real,
    se necessário.
    """
    return round(
        random.uniform(
            MIN_TEMPERATURE,
            MAX_TEMPERATURE
        ),
        2
    )


# --------------------------------------------------
# SEND TEMPERATURE
# --------------------------------------------------

def send_temperature(temperature):
    """
    Envia uma leitura ao Ingestion e verifica
    se o pedido foi aceite.
    """
    global cached_ingestion_url, last_discovery_time

    payload = {
        "device_id": DEVICE_ID,
        "temperature": temperature
    }

    try:
        ingestion_url = discover_ingestion()

        response = requests.post(
            f"{ingestion_url}/ingest",
            json=payload,
            timeout=INGESTION_TIMEOUT
        )

        if response.ok:
            print(
                f"Temperatura enviada: {temperature} °C "
                f"(sensor: {DEVICE_ID})"
            )
            return True

        print(
            f"Ingestion respondeu HTTP {response.status_code}: "
            f"{response.text}"
        )

        if response.status_code >= 500:
            cached_ingestion_url = None
            last_discovery_time = 0

        return False

    except (requests.RequestException, RuntimeError) as e:
        print("Falha ao enviar temperatura:", e)

        cached_ingestion_url = None
        last_discovery_time = 0

        return False


# --------------------------------------------------
# MAIN LOOP
# --------------------------------------------------

def main():
    if not DEVICE_ID.strip():
        raise ValueError("DEVICE_ID não pode estar vazio")

    if SENSOR_INTERVAL <= 0:
        raise ValueError(
            "SENSOR_INTERVAL tem de ser maior que zero"
        )

    print(f"Sensor iniciado: {DEVICE_ID}")
    print(f"Registry: {REGISTRY_URL}")
    print(f"Intervalo: {SENSOR_INTERVAL} segundos")
    print(
        f"Localização: {COUNTRY}/{REGION}/"
        f"{DC}/{RACK}/{NODE}"
    )

    # Inicia o registo e o heartbeat em segundo plano.
    threading.Thread(
        target=heartbeat,
        daemon=True
    ).start()

    failure_delay = 1
    max_failure_delay = 30

    while True:
        temperature = read_temperature()

        if send_temperature(temperature):
            failure_delay = 1
            time.sleep(SENSOR_INTERVAL)

        else:
            print(
                f"Nova tentativa em {failure_delay} segundos..."
            )
            time.sleep(failure_delay)

            failure_delay = min(
                failure_delay * 2,
                max_failure_delay
            )


if __name__ == "__main__":
    main()
