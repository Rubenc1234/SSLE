import requests
import json
import argparse
from datetime import datetime

PROMETHEUS_URL = "http://10.255.255.27:9090/api/v1/query"

SERVICES = {
    "registry-pt-aveiro-dc1-r01-n01": "registry-pt-aveiro-dc1-r01-n01.incus:5050",
    "storage-pt-aveiro-dc1-r02-n01": "storage-pt-aveiro-dc1-r02-n01.incus:5002",
    "ingestion-pt-aveiro-dc1-r01-n02": "ingestion-pt-aveiro-dc1-r01-n02.incus:5001",
    "analytics-pt-aveiro-dc1-r02-n02": "analytics-pt-aveiro-dc1-r02-n02.incus:5003",
}

def query_prometheus(promql):
    """
    Executa uma instant query no Prometheus.

    Devolve:
        float  -> valor numerico da metrica (incluindo 0.0, que e um
                  resultado legitimo: a query correu bem mas o valor e zero)
        None   -> falha real (erro de rede, timeout, erro de sintaxe PromQL,
                  ou qualquer resposta que nao seja "status": "success")

    Nunca confundir None com 0.0 ao analisar os resultados depois.
    """
    try:
        response = requests.get(
            PROMETHEUS_URL,
            params={"query": promql},
            timeout=5
        )
        data = response.json()
    except Exception as e:
        print(f"[AVISO] Falha de ligacao a executar query: {promql} | Erro: {e}")
        return None

    if data.get("status") != "success":
        print(
            f"[AVISO] Prometheus devolveu erro para a query: {promql} "
            f"| Detalhe: {data.get('error', 'sem detalhe')}"
        )
        return None

    result = data.get("data", {}).get("result", [])

    if not result:
        # Query valida, mas sem series correspondentes (ex: metrica ainda
        # nao foi incrementada nenhuma vez). Isto e diferente de uma falha.
        return 0.0

    return float(result[0]["value"][1])


def fmt(value, unit="", decimals=2):
    """Formata um valor para impressao, lidando com None sem rebentar."""
    if value is None:
        return "N/A"

    return f"{value:.{decimals}f}{unit}"


def main():
    parser = argparse.ArgumentParser(
        description="Recolha de telemetria para o projeto SSLE"
    )
    parser.add_argument(
        "--label",
        type=str,
        default="baseline",
        help="Nome do cenario (ex: baseline, attack_A1, mitigation_A1)",
    )
    args = parser.parse_args()

    print(
        f"=== TELEMETRIA SSLE [{args.label.upper()}] - "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ==="
    )

    report = {
        "scenario": args.label,
        "timestamp": datetime.now().isoformat(),
        "infrastructure": {},
        "services": {},
        "business": {},
    }

    # --------------------------------------------------------------
    # 1. Infraestrutura — CPU e RAM por contentor (via incus_exporter)
    # --------------------------------------------------------------
    print("\n[+] A recolher metricas de Infraestrutura (Incus)...")

    for container in SERVICES.keys():
        cpu_avg = query_prometheus(
            f'avg_over_time(incus_container_cpu_usage_percent'
            f'{{container="{container}"}}[10m])'
        )
        cpu_max = query_prometheus(
            f'max_over_time(incus_container_cpu_usage_percent'
            f'{{container="{container}"}}[10m])'
        )
        ram_avg_bytes = query_prometheus(
            f'avg_over_time(incus_container_memory_usage_bytes'
            f'{{container="{container}"}}[10m])'
        )
        ram_max_bytes = query_prometheus(
            f'max_over_time(incus_container_memory_usage_bytes'
            f'{{container="{container}"}}[10m])'
        )

        ram_avg_mib = (
            ram_avg_bytes / (1024 * 1024) if ram_avg_bytes is not None else None
        )
        ram_max_mib = (
            ram_max_bytes / (1024 * 1024) if ram_max_bytes is not None else None
        )

        report["infrastructure"][container] = {
            "cpu_avg_percent": cpu_avg,
            "cpu_max_percent": cpu_max,
            "ram_avg_mib": ram_avg_mib,
            "ram_max_mib": ram_max_mib,
        }

        print(
            f" -> {container}: "
            f"CPU media={fmt(cpu_avg, '%')}, CPU max={fmt(cpu_max, '%')}, "
            f"RAM media={fmt(ram_avg_mib, ' MiB')}, RAM max={fmt(ram_max_mib, ' MiB')}"
        )

    # --------------------------------------------------------------
    # 2. RED por servico — Rate, Errors, Latencia p95
    # --------------------------------------------------------------
    print("\n[+] A recolher metricas RED por Servico...")

    for container, instance in SERVICES.items():
        rps = query_prometheus(
            f'sum(rate(http_requests_total{{instance="{instance}"}}[5m]))'
        )
        errors = query_prometheus(
            f'sum(rate(http_requests_total'
            f'{{instance="{instance}", status=~"4..|5.."}}[5m]))'
        )
        latency_p95 = query_prometheus(
            f'histogram_quantile(0.95, sum(rate('
            f'http_request_duration_seconds_bucket{{instance="{instance}"}}[5m]'
            f')) by (le))'
        )

        report["services"][container] = {
            "rps": rps,
            "error_rate": errors,
            "latency_p95_seconds": latency_p95,
        }

        print(
            f" -> {container}: "
            f"RPS={fmt(rps, '', 3)}, Erros/s={fmt(errors, '', 3)}, "
            f"Latencia p95={fmt(latency_p95, 's', 4)}"
        )

    # --------------------------------------------------------------
    # 3. Ramo A — payload size (so existe no Ingestion, sem label instance)
    # --------------------------------------------------------------
    print("\n[+] A recolher metrica de Payload Size (Ramo A / A2)...")

    payload_p95 = query_prometheus(
        "histogram_quantile(0.95, sum(rate("
        "request_body_size_bytes_bucket[5m])) by (le))"
    )
    report["services"]["ingestion_payload_p95_bytes"] = payload_p95

    print(f" -> Payload p95 (Ingestion): {fmt(payload_p95, ' bytes')}")

    # --------------------------------------------------------------
    # 4. Ramos B e C — metricas de negocio no Registry/Storage
    # --------------------------------------------------------------
    print("\n[+] A recolher metricas de Negocio (Ramos B e C)...")

    sensor_registrations = query_prometheus(
        'sum(increase(registry_registrations_total{name="sensor"}[10m]))'
    )
    unique_devices = query_prometheus(
	    'storage_unique_devices_total{instance="storage-pt-aveiro-dc1-r02-n01.incus:5002"}'
	)
    registry_overwrites = query_prometheus("registry_overwrites_total")
    storage_entries = query_prometheus(
        'registry_entries_per_name{name="storage-service"}'
    )
    ingestion_entries = query_prometheus(
        'registry_entries_per_name{name="ingestion-service"}'
    )

    report["business"] = {
        "sensor_registrations_10m": sensor_registrations,
        "storage_unique_devices": unique_devices,
        "registry_overwrites_total": registry_overwrites,
        "registry_entries_storage": storage_entries,
        "registry_entries_ingestion": ingestion_entries,
    }

    print(f" -> Registos de Sensores (10m): {fmt(sensor_registrations, '', 0)}")
    print(f" -> Dispositivos Unicos (Storage): {fmt(unique_devices, '', 0)}")
    print(f" -> Registry Overwrites: {fmt(registry_overwrites, '', 0)}")
    print(f" -> Entradas 'storage-service' no Registry: {fmt(storage_entries, '', 0)}")
    print(f" -> Entradas 'ingestion-service' no Registry: {fmt(ingestion_entries, '', 0)}")

    # --------------------------------------------------------------
    # Guardar relatorio
    # --------------------------------------------------------------
    filename = f"ssle_report_{args.label}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[INFO] Relatorio guardado com sucesso em '{filename}'!")


if __name__ == "__main__":
    main()