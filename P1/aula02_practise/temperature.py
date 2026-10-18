
import os
import time
import random
import requests

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

REGISTRY_URL = os.environ.get(
    "REGISTRY_URL",
    "http://localhost:5050"
).rstrip("/")

INGESTION_URL = os.environ.get(
    "INGESTION_URL",
    "http://localhost:5001"
).rstrip("/")

DEVICE_ID = os.environ.get(
    "DEVICE_ID",
    "sensor-pt-cen-dc1-r02-n03"
)

SENSOR_INTERVAL = float(
    os.environ.get("SENSOR_INTERVAL", "5")
)

REGISTRY_TIMEOUT = 3
INGESTION_TIMEOUT = 5

MIN_TEMPERATURE = 20.0
MAX_TEMPERATURE = 30.0

# Cache do endereço do Ingestion
cached_ingestion_url = None
last_discovery_time = 0
DISCOVERY_CACHE_TTL = 10


# --------------------------------------------------
# INGESTION DISCOVERY
# --------------------------------------------------

def discover_ingestion():
    """
    Descobre o serviço Ingestion através do Registry.
    Mantém o último endereço conhecido para tolerar
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

    except (requests.RequestException, ValueError, RuntimeError) as e:
        print(f"Erro ao descobrir Ingestion: {e}")

        if cached_ingestion_url:
            print("A utilizar o último endereço conhecido.")
            return cached_ingestion_url

        # Permite tentar novamente na próxima iteração.
        last_discovery_time = 0
        raise RuntimeError(
            "Não foi possível descobrir o serviço Ingestion"
        ) from e


# --------------------------------------------------
# TEMPERATURE GENERATION
# --------------------------------------------------

def read_temperature():
    """
    Simula a leitura de um sensor de temperatura.
    Substituir por uma leitura real quando existir hardware.
    """
    return round(
        random.uniform(MIN_TEMPERATURE, MAX_TEMPERATURE),
        2
    )


# --------------------------------------------------
# SEND TEMPERATURE
# --------------------------------------------------

def send_temperature(temperature):
    """
    Envia uma leitura ao Ingestion.
    Só considera o envio bem-sucedido se o serviço
    responder com um código HTTP de sucesso.
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
            f"Ingestion rejeitou o pedido: "
            f"HTTP {response.status_code} - {response.text}"
        )

        # Se o serviço estiver indisponível, força nova descoberta.
        if response.status_code >= 500:
            cached_ingestion_url = None
            last_discovery_time = 0

        return False

    except (requests.RequestException, RuntimeError) as e:
        print(f"Falha ao enviar temperatura: {e}")

        # Voltar a descobrir o Ingestion na próxima tentativa.
        cached_ingestion_url = None
        last_discovery_time = 0

        return False


# --------------------------------------------------
# MAIN LOOP WITH BACKOFF
# --------------------------------------------------

def main():
    if not DEVICE_ID.strip():
        raise ValueError("DEVICE_ID não pode estar vazio")

    if SENSOR_INTERVAL <= 0:
        raise ValueError("SENSOR_INTERVAL tem de ser maior que zero")

    print(f"Sensor iniciado: {DEVICE_ID}")
    print(f"Registry: {REGISTRY_URL}")
    print(f"Intervalo: {SENSOR_INTERVAL} segundos")

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
