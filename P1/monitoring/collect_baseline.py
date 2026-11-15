
import requests
import json
import argparse
from datetime import datetime, timezone

PROMETHEUS_URL = "http://10.255.255.27:9090/api/v1/query"

# Preenchidos no main() a partir de --window / --at
WINDOW = "10m"
AT = None

SERVICES = {
    "registry-pt-aveiro-dc1-r01-n01": "registry-pt-aveiro-dc1-r01-n01.incus:5050",
    "storage-pt-aveiro-dc1-r02-n01": "storage-pt-aveiro-dc1-r02-n01.incus:5002",
    "ingestion-pt-aveiro-dc1-r01-n02": "ingestion-pt-aveiro-dc1-r01-n02.incus:5001",
    "analytics-pt-aveiro-dc1-r02-n02": "analytics-pt-aveiro-dc1-r02-n02.incus:5003",
}

# Seletor do /ingest no Ingestion (regex no label endpoint, por precaucao)
ING = 'instance=~"ingestion.*",endpoint=~".*ingest.*"'


def query_prometheus(promql):
    """
    Instant query. Devolve float, 0.0 se a query for valida mas sem series,
    ou None em falha real. Os marcadores {W} (janela), {I} (instance) e
    {C} (container) sao substituidos em Q().
    """
    promql = promql.replace("{W}", WINDOW)
    params = {"query": promql}
    if AT:
        params["time"] = AT
    try:
        response = requests.get(PROMETHEUS_URL, params=params, timeout=15)
        data = response.json()
    except Exception as e:
        print(f"[AVISO] Falha de ligacao: {promql} | Erro: {e}")
        return None

    if data.get("status") != "success":
        print(f"[AVISO] Erro do Prometheus: {promql} | {data.get('error', 'sem detalhe')}")
        return None

    result = data.get("data", {}).get("result", [])
    if not result:
        return 0.0
    # Todas as queries abaixo agregam (sum/max) ou filtram uma so serie.
    return float(result[0]["value"][1])


def Q(template, instance=None, container=None):
    if instance:
        template = template.replace("{I}", instance)
    if container:
        template = template.replace("{C}", container)
    return query_prometheus(template)


def fmt(value, unit="", decimals=2):
    if value is None:
        return "N/A"
    return f"{value:.{decimals}f}{unit}"


def main():
    global WINDOW, AT

    parser = argparse.ArgumentParser(description="Recolha de telemetria SSLE")
    parser.add_argument("--label", default="baseline")
    parser.add_argument("--window", default="10m",
                        help="Janela de medicao, ex: 90s, 150s")
    parser.add_argument("--at", type=int, default=None,
                        help="Instante final da janela (epoch, segundos)")
    args = parser.parse_args()
    WINDOW, AT = args.window, args.at

    at_utc = (datetime.fromtimestamp(AT, timezone.utc).isoformat()
              if AT else "now")
    print(f"=== TELEMETRIA SSLE [{args.label.upper()}] janela={WINDOW} "
          f"fim={at_utc} ===")

    report = {
        "scenario": args.label,
        "timestamp": datetime.now().isoformat(),
        "window": WINDOW,
        "at": AT,
        "at_utc": at_utc,
        "data_ok": True,
        "infrastructure": {},
        "services": {},
        "ingestion_extra": {},
        "business": {},
    }

    # 1. Infraestrutura (media e pico na janela)
    print("\n[+] Infraestrutura (Incus)...")
    for c in SERVICES:
        cpu_avg = Q('avg_over_time(incus_container_cpu_usage_percent{container="{C}"}[{W}])', container=c)
        cpu_max = Q('max_over_time(incus_container_cpu_usage_percent{container="{C}"}[{W}])', container=c)
        ram_avg = Q('avg_over_time(incus_container_memory_usage_bytes{container="{C}"}[{W}])', container=c)
        ram_max = Q('max_over_time(incus_container_memory_usage_bytes{container="{C}"}[{W}])', container=c)
        mib = lambda v: v / (1024 * 1024) if v is not None else None
        report["infrastructure"][c] = {
            "cpu_avg_percent": cpu_avg,
            "cpu_max_percent": cpu_max,
            "ram_avg_mib": mib(ram_avg),
            "ram_max_mib": mib(ram_max),
        }
        print(f" -> {c}: CPU media={fmt(cpu_avg, '%')}, CPU max={fmt(cpu_max, '%')}, "
              f"RAM media={fmt(mib(ram_avg), ' MiB')}, RAM max={fmt(mib(ram_max), ' MiB')}")

    if not any(v["ram_avg_mib"] for v in report["infrastructure"].values()):
        report["data_ok"] = False
        print("[AVISO] Sem dados de RAM em nenhum contentor: janela fora da "
              "retencao do Prometheus ou instante errado. Este JSON NAO e valido.")

    # 2. RED por servico (medias da janela + pedidos totais)
    print("\n[+] RED por servico...")
    for c, inst in SERVICES.items():
        rps = Q('sum(rate(http_requests_total{instance="{I}"}[{W}]))', instance=inst)
        errors = Q('sum(rate(http_requests_total{instance="{I}",status=~"4..|5.."}[{W}]))', instance=inst)
        p95 = Q('histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{instance="{I}"}[{W}])) by (le))', instance=inst)
        total = Q('sum(increase(http_requests_total{instance="{I}"}[{W}]))', instance=inst)
        report["services"][c] = {
            "rps": rps,
            "error_rate": errors,
            "latency_p95_seconds": p95,
            "requests_window": total,
        }
        print(f" -> {c}: RPS={fmt(rps, '', 3)}, Erros/s={fmt(errors, '', 3)}, "
              f"p95={fmt(p95, 's', 4)}, pedidos={fmt(total, '', 0)}")

    payload_p95 = Q('histogram_quantile(0.95, sum(rate(request_body_size_bytes_bucket[{W}])) by (le))')
    report["services"]["ingestion_payload_p95_bytes"] = payload_p95
    print(f" -> Payload p95 (Ingestion): {fmt(payload_p95, ' bytes')}")

    # 3. /ingest no Ingestion (o que o servidor realmente serviu)
    print("\n[+] /ingest no Ingestion...")
    served = Q('sum(increase(http_requests_total{' + ING + '}[{W}]))')
    served_2xx = Q('sum(increase(http_requests_total{' + ING + ',status=~"2.."}[{W}]))')
    served_5xx = Q('sum(increase(http_requests_total{' + ING + ',status=~"5.."}[{W}]))')
    peak = Q('max_over_time(sum(rate(http_requests_total{' + ING + '}[45s]))[{W}:5s])')
    report["ingestion_extra"] = {
        "ingest_requests_window": served,
        "ingest_2xx_window": served_2xx,
        "ingest_5xx_window": served_5xx,
        "ingest_peak_rps_45s": peak,
    }
    print(f" -> pedidos={fmt(served, '', 0)}, 2xx={fmt(served_2xx, '', 0)}, "
          f"5xx={fmt(served_5xx, '', 0)}, pico RPS (suavizado 45 s)={fmt(peak, '', 2)}")
    ing_total = report["services"]["ingestion-pt-aveiro-dc1-r01-n02"]["requests_window"]
    if served == 0.0 and ing_total and ing_total > 5:
        print("[AVISO] O seletor do /ingest nao apanhou nada mas o Ingestion "
              "teve pedidos: confirma os valores do label 'endpoint'.")

    # 4. Negocio (todas filtradas/agregadas por instance)
    print("\n[+] Negocio...")
    reg_posts = Q('sum(increase(http_requests_total{instance=~"registry.*",endpoint=~".*register.*"}[{W}]))')
    sensor_regs = Q('sum(increase(registry_registrations_total{name="sensor"}[{W}]))')
    unique_dev = Q('max(max_over_time(storage_unique_devices_total{instance=~"storage.*"}[{W}]))')
    overwrites = Q('max(max_over_time(registry_overwrites_total{instance=~"registry.*"}[{W}]))')
    st_entries = Q('max(registry_entries_per_name{name="storage-service",instance=~"registry.*"})')
    in_entries = Q('max(registry_entries_per_name{name="ingestion-service",instance=~"registry.*"})')
    report["business"] = {
        "registry_register_requests_window": reg_posts,
        "sensor_registrations_window": sensor_regs,
        "storage_unique_devices": unique_dev,
        "registry_overwrites": overwrites,
        "registry_entries_storage": st_entries,
        "registry_entries_ingestion": in_entries,
    }
    print(f" -> POST /register no Registry: {fmt(reg_posts, '', 0)}")
    print(f" -> Registos de sensores (janela): {fmt(sensor_regs, '', 0)}")
    print(f" -> Dispositivos unicos (Storage, max): {fmt(unique_dev, '', 0)}")
    print(f" -> Registry overwrites (max): {fmt(overwrites, '', 0)}")
    print(f" -> Entradas storage-service: {fmt(st_entries, '', 0)} | "
          f"ingestion-service: {fmt(in_entries, '', 0)}")

    filename = f"ssle_report_{args.label}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[INFO] Relatorio guardado em '{filename}' (data_ok={report['data_ok']})")


if __name__ == "__main__":
    main()
