import subprocess
import json
import time
import threading
from flask import Flask, Response
from prometheus_client import Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Métricas por container
CPU_USAGE = Gauge(
    "incus_container_cpu_usage_percent",
    "CPU usage percentage",
    ["container"]
)
MEMORY_USAGE = Gauge(
    "incus_container_memory_usage_bytes",
    "Memory usage in bytes",
    ["container"]
)
MEMORY_TOTAL = Gauge(
    "incus_container_memory_total_bytes",
    "Total memory available in bytes",
    ["container"]
)
PROCESS_COUNT = Gauge(
    "incus_container_processes",
    "Number of processes",
    ["container"]
)
INCUS_CONTAINER_UP = Gauge(
    "incus_container_up",
    "Whether Incus container metrics collection succeeded",
    ["container"]
)

CONTAINERS = [
    "registry-pt-aveiro-dc1-r01-n01",
    "storage-pt-aveiro-dc1-r02-n01",
    "ingestion-pt-aveiro-dc1-r01-n02",
    "analytics-pt-aveiro-dc1-r02-n02",
    "prometheus-container",
]

previous_cpu = {}
previous_time = {}

def background_collector():
    """Recolhe métricas em background de forma assíncrona a cada 5 segundos."""
    while True:
        now = time.monotonic()
        for name in CONTAINERS:
            try:
                result = subprocess.run(
                    ["incus", "query", f"/1.0/instances/{name}/state"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=3  # Timeout de segurança sugerido
                )
                state = json.loads(result.stdout)

                # RAM e Processos
                MEMORY_USAGE.labels(name).set(state["memory"]["usage"])
                MEMORY_TOTAL.labels(name).set(state["memory"]["total"])
                PROCESS_COUNT.labels(name).set(state["processes"])

                # CPU Delta
                cpu_now = state["cpu"]["usage"]
                if name in previous_cpu:
                    cpu_delta = cpu_now - previous_cpu[name]
                    time_delta = now - previous_time[name]
                    if time_delta > 0 and cpu_delta >= 0:
                        cpu_percent = (cpu_delta / (time_delta * 1e9)) * 100
                        CPU_USAGE.labels(name).set(cpu_percent)

                previous_cpu[name] = cpu_now
                previous_time[name] = now

                # Sucesso na recolha
                INCUS_CONTAINER_UP.labels(name).set(1)

            except Exception as e:
                print(f"Erro ao recolher métricas de {name}: {e}")
                # Marca como falha no Prometheus se o contentor falhar
                INCUS_CONTAINER_UP.labels(name).set(0)
        
        time.sleep(5)

@app.route("/metrics")
def metrics():
    # O endpoint serve instantaneamente o que está em memória na thread
    return Response(
        generate_latest(),
        mimetype=CONTENT_TYPE_LATEST
    )

if __name__ == "__main__":
    # Inicia a thread de recolha em background
    t = threading.Thread(target=background_collector, daemon=True)
    t.start()
    
    # Arranca o servidor Flask do exporter na porta 9101 na máquina anfitriã
    app.run(host="0.0.0.0", port=9101)