#!/usr/bin/env python3
"""
graficos.py - gera PNGs (e CSVs com os dados brutos) a partir do Prometheus
para cada corrida de evidencias/, em graficos/<corrida>/<id>_<nome>.png
Ou figuras compostas comparativas com --compor dos botnet hijack.

Uso (na raiz de P1, com o venv ativo):
  python3 monitoring/graficos.py --listar                 # so mostra o what faria
  python3 monitoring/graficos.py --only dos_r2            # uma corrida
  python3 monitoring/graficos.py --compor dos botnet hijack # gera figuras compostas para o relatorio
  python3 monitoring/graficos.py --rate 30s               # janela do rate()/increase()

Janela do grafico: de (start - 60 s) ate (at + 30 s), step 15 s (= scrape).
Linhas verticais: inicio/fim do ataque (meta.txt) e alertas Wazuh
(100201, 100211, 100220, 651, 652) lidos de evidencias/_wazuh/.
"""
import argparse, csv, glob, json, os, sys
from datetime import datetime, timezone
import requests
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

PROM = "http://10.255.255.27:9090/api/v1/query_range"
STEP = 15
PAD_BEFORE, PAD_AFTER = 60, 30
OFFSET = {"dos": 130, "normal": 130, "botnet": 70, "hijack": 70}
ALERT_IDS = {"100201": "tab:red", "100211": "tab:orange", "100220": "tab:purple",
             "651": "black", "652": "tab:green"}
ALERT_TXT = {"100201": "100201 DoS", "100211": "100211 botnet", "100220": "100220 hijack",
             "651": "651 bloqueio", "652": "652 desbloqueio"}

# id -> (nome, titulo, query com {R}, divisor, eixo Y)
Q = {
 "A1": ("ingest_por_status", "Ingestion /ingest: pedidos/s por status",
        'sum by (status)(rate(http_requests_total{instance=~"ingestion.*",endpoint="/ingest"}[{R}]))', 1, "pedidos/s"),
 "A2": ("ingest_p95", "Ingestion /ingest: latencia p95",
        'histogram_quantile(0.95, sum by (le)(rate(http_request_duration_seconds_bucket{instance=~"ingestion.*",endpoint="/ingest"}[{R}])))', 1, "segundos"),
 "A4": ("cpu_ingestion", "CPU do Ingestion", 'incus_container_cpu_usage_percent{container=~"ingestion.*"}', 1, "%"),
 "A5": ("cpu_storage", "CPU do Storage", 'incus_container_cpu_usage_percent{container=~"storage.*"}', 1, "%"),
 "A6": ("ram_ingestion", "RAM do Ingestion", 'incus_container_memory_usage_bytes{container=~"ingestion.*"}', 1048576, "MiB"),
 "A7": ("store_storage", "Storage /store: pedidos/s",
        'sum(rate(http_requests_total{instance=~"storage.*",endpoint="/store"}[{R}]))', 1, "pedidos/s"),
 "B1": ("register_registry", "Registry /register: pedidos na janela",
        'sum(increase(http_requests_total{instance=~"registry.*",endpoint="/register"}[{R}]))', 1, "pedidos"),
 "B2": ("registos_sensor", "Registos com name=sensor (increase)",
        'sum(increase(registry_registrations_total{name="sensor"}[{R}]))', 1, "registos"),
 "B3": ("entradas_sensor", "Entradas de sensores vivas no Registry",
        'registry_entries_per_name{name="sensor"}', 1, "entradas"),
 "B4": ("registry_por_endpoint", "Registry: pedidos/s por endpoint",
        'sum by (endpoint)(rate(http_requests_total{instance=~"registry.*"}[{R}]))', 1, "pedidos/s"),
 "B5": ("ingest_total", "Ingestion /ingest: pedidos/s (total)",
        'sum(rate(http_requests_total{instance=~"ingestion.*",endpoint="/ingest"}[{R}]))', 1, "pedidos/s"),
 "B6": ("dispositivos_unicos", "Storage: dispositivos unicos",
        'max(storage_unique_devices_total{instance=~"storage.*"})', 1, "dispositivos"),
 "C1": ("ingest_por_status", "Ingestion /ingest: pedidos/s por status",
        'sum by (status)(rate(http_requests_total{instance=~"ingestion.*",endpoint="/ingest"}[{R}]))', 1, "pedidos/s"),
 "C3": ("store_storage", "Storage /store: pedidos/s",
        'sum(rate(http_requests_total{instance=~"storage.*",endpoint="/store"}[{R}]))', 1, "pedidos/s"),
 "C4": ("descobertas_registry", "Registry /services/<name>: pedidos/s",
        'sum(rate(http_requests_total{instance=~"registry.*",endpoint="/services/<service_name>"}[{R}]))', 1, "pedidos/s"),
 "C5": ("reregistos_service_id", "registry_overwrites_total (re-registos de service_id, NAO e detetor de hijack)",
        'max(registry_overwrites_total{instance=~"registry.*"})', 1, "contador"),
}
SETS = {
 "dos": ["A1", "A2", "A4", "A5", "A6", "A7"],
 "botnet": ["B1", "B2", "B3", "B4", "B5", "B6"],
 "hijack": ["C1", "C3", "C4", "C5", "A2"],
 "normal": ["A1", "A2", "A4", "B4", "B6"],
}


def parse_ts(s):
    s = s.strip().replace("+0000", "+00:00")
    return datetime.fromisoformat(s).timestamp()


def read_meta(d):
    m = {}
    p = os.path.join(d, "meta.txt")
    if not os.path.isfile(p):
        return None
    for line in open(p):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            m[k] = v
    return m


def load_alerts():
    files = glob.glob("evidencias/_wazuh/**/*.json", recursive=True)
    seen, out = set(), []
    for f in files:
        for line in open(f, errors="replace"):
            try:
                a = json.loads(line)
            except Exception:
                continue
            rid = a.get("rule", {}).get("id")
            if rid not in ALERT_IDS:
                continue
            key = (a["timestamp"], rid, a.get("agent", {}).get("name"))
            if key in seen:
                continue
            seen.add(key)
            out.append((parse_ts(a["timestamp"]), rid, a.get("agent", {}).get("name", "")))
    return sorted(out)


def label_of(metric):
    parts = [f"{k}={v}" for k, v in metric.items() if k not in ("__name__", "job")]
    return ", ".join(parts) if parts else "total"


def query_range(q, t0, t1):
    r = requests.get(PROM, params={"query": q, "start": t0, "end": t1, "step": STEP}, timeout=30)
    j = r.json()
    if j.get("status") != "success":
        raise RuntimeError(j.get("error", "erro do Prometheus"))
    return j["data"]["result"]


def plot_one(qid, rate, t0, t1, meta_marks, alerts, outdir, name):
    nome, titulo, tmpl, div, ylab = Q[qid]
    q = tmpl.replace("{R}", rate)
    res = query_range(q, t0, t1)
    if not res:
        return f"SEM DADOS  {qid} {nome}"
    fig, ax = plt.subplots(figsize=(10, 4.5))
    rows, vmax, npts = [], 0.0, 0
    for s in res:
        xs = [datetime.fromtimestamp(float(t), timezone.utc) for t, _ in s["values"]]
        ys = [float(v) / div if v not in ("NaN", "+Inf", "-Inf") else float("nan") for _, v in s["values"]]
        lab = label_of(s["metric"])
        ax.plot(xs, ys, marker=".", label=lab)
        for t, y in zip(xs, ys):
            rows.append([t.isoformat(), lab, y])
        good = [y for y in ys if y == y]
        if good:
            vmax = max(vmax, max(good))
        npts += len(ys)
    for t, txt, col in meta_marks:
        ax.axvline(datetime.fromtimestamp(t, timezone.utc), color=col, linestyle="--", linewidth=1)
        ax.text(datetime.fromtimestamp(t, timezone.utc), ax.get_ylim()[1], txt, rotation=90,
                va="top", ha="right", fontsize=7, color=col)
    for t, rid, ag in alerts:
        if t0 <= t <= t1:
            ax.axvline(datetime.fromtimestamp(t, timezone.utc), color=ALERT_IDS[rid], linestyle=":", linewidth=1.3)
            ax.text(datetime.fromtimestamp(t, timezone.utc), ax.get_ylim()[1], ALERT_TXT[rid],
                    rotation=90, va="top", ha="left", fontsize=7, color=ALERT_IDS[rid])
    ax.set_title(f"{name} - {titulo}\n[{rate}] scrape 15 s, UTC", fontsize=10)
    ax.set_ylabel(ylab)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    ax.grid(alpha=0.3)
    if len(res) > 1:
        ax.legend(fontsize=7)
    fig.autofmt_xdate()
    fig.tight_layout()
    base = os.path.join(outdir, f"{qid}_{nome}")
    fig.savefig(base + ".png", dpi=130)
    plt.close(fig)
    with open(base + ".csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time_utc", "serie", "valor"])
        w.writerows(rows)
    return f"ok         {qid} {nome}: {len(res)} serie(s), {npts} pontos, max={vmax:.4g}"


# --------------------------------------------------------------------
# Figuras compostas para o relatorio: 3 colunas (baseline | ataque | Wazuh)
# x 2 linhas (carga/comportamento e impacto), eixo Y PARTILHADO por linha
# e eixo X em segundos desde o inicio da corrida (colunas comparaveis).
# --------------------------------------------------------------------
FIGS = {
    "dos": (["normal_r2", "dos_r2", "dos_wazuh_ar_r2"], ["A1", "A4"],
            ["Baseline (normal)", "Ataque sem mitigacao", "Ataque + Wazuh (bloqueio)"]),
    "botnet": (["normal_r2", "botnet_r2", "botnet_wazuh_ar_ab_r2"], ["B1", "B6"],
               ["Baseline (normal)", "Ataque sem mitigacao", "Ataque + Wazuh (bloqueio A+B)"]),
    "hijack": (["normal_r2", "hijack_r2", "hijack_wazuh_r2"], ["C1", "C3"],
               ["Baseline (normal)", "Ataque sem Wazuh", "Ataque + Wazuh (so deteccao, sem bloqueio)"]),
}


def run_times(name):
    meta = read_meta(os.path.join("evidencias", name))
    if not meta or "start" not in meta:
        raise SystemExit(f"[ERRO] evidencias/{name}/meta.txt em falta ou sem start")
    tipo = name.split("_")[0]
    start = parse_ts(meta["start"])
    at = float(meta["at_epoch"]) if "at_epoch" in meta else start + OFFSET[tipo]
    end = parse_ts(meta["end"]) if "end" in meta else None
    return tipo, start, at, end


def compor(tipo, rate):
    cols, rows, titles = FIGS[tipo]
    alerts = load_alerts()
    xmax = OFFSET[tipo] + PAD_AFTER
    fig, axes = plt.subplots(len(rows), len(cols), figsize=(15, 3.8 * len(rows)),
                             sharey="row", squeeze=False)
    colors, handles = {}, {}
    for j, name in enumerate(cols):
        ctipo, start, at, end = run_times(name)
        t0, t1 = start - PAD_BEFORE, at + PAD_AFTER
        for i, qid in enumerate(rows):
            ax = axes[i][j]
            _, titulo, tmpl, div, ylab = Q[qid]
            for s in query_range(tmpl.replace("{R}", rate), t0, t1):
                lab = label_of(s["metric"])
                col = colors.setdefault(lab, f"C{len(colors) % 10}")
                xs = [float(t) - start for t, _ in s["values"]]
                ys = [float(v) / div if v not in ("NaN", "+Inf", "-Inf") else float("nan")
                      for _, v in s["values"]]
                h, = ax.plot(xs, ys, marker=".", color=col, label=lab)
                handles.setdefault(lab, h)
            if ctipo != "normal":
                ax.axvline(0, color="gray", linestyle="--", linewidth=1)
                if end is not None and end - start > 2:
                    ax.axvline(end - start, color="gray", linestyle="--", linewidth=1)
                for t, rid, ag in alerts:
                    if t0 <= t <= t1:
                        ax.axvline(t - start, color=ALERT_IDS[rid], linestyle=":", linewidth=1.4)
                        if i == 0:
                            ax.text(t - start, 1.0, ALERT_TXT[rid], transform=ax.get_xaxis_transform(),
                                    rotation=90, va="top", ha="right", fontsize=7, color=ALERT_IDS[rid])
            ax.set_xlim(-PAD_BEFORE, xmax)
            ax.grid(alpha=0.3)
            if i == 0:
                ax.set_title(f"{titles[j]}\n({name})", fontsize=10)
            if j == 0:
                ax.set_ylabel(f"{titulo}\n[{ylab}]", fontsize=8)
            if i == len(rows) - 1:
                ax.set_xlabel("segundos desde o inicio da corrida (UTC)")
    if handles:
        fig.legend(handles.values(), handles.keys(), loc="lower right", fontsize=8, ncol=len(handles))
    fig.text(0.01, 0.005,
             f"Prometheus: janela [{rate}], scrape 15 s (rate/increase sao estimativas). "
             "Contagens exatas: evidencias/_verificacao.txt. Linhas tracejadas: inicio/fim do ataque; "
             "pontilhadas: alertas Wazuh.", fontsize=7)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    out = os.path.join("graficos", "_figuras", f"{tipo}_{rate}.png")
    fig.savefig(out, dpi=140)
    plt.close(fig)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--rate", default="1m")
    ap.add_argument("--listar", action="store_true")
    ap.add_argument("--compor", nargs="+", choices=list(FIGS),
                    help="gera a figura composta (baseline|ataque|Wazuh) por ameaca")
    a = ap.parse_args()
    if a.compor:
        os.makedirs(os.path.join("graficos", "_figuras"), exist_ok=True)
        for tipo in a.compor:
            print("[ok]", compor(tipo, a.rate))
        return

    dirs = sorted(d for d in glob.glob("evidencias/*/") if not os.path.basename(d.rstrip("/")).startswith("_"))
    alerts = load_alerts()
    print(f"[info] {len(alerts)} alertas Wazuh carregados de evidencias/_wazuh/")
    os.makedirs("graficos", exist_ok=True)
    index = []
    for d in dirs:
        name = os.path.basename(d.rstrip("/"))
        if a.only and name not in a.only:
            continue
        tipo = name.split("_")[0]
        meta = read_meta(d)
        if tipo not in SETS or not meta or "start" not in meta:
            print(f"[skip] {name}: sem tipo/meta valido")
            continue
        start = parse_ts(meta["start"])
        at = float(meta["at_epoch"]) if "at_epoch" in meta else start + OFFSET[tipo]
        t0, t1 = start - PAD_BEFORE, at + PAD_AFTER
        marks = [(start, "inicio ataque", "gray")]
        if "end" in meta:
            marks.append((parse_ts(meta["end"]), "fim ataque", "gray"))
        print(f"\n== {name} ({tipo}) {datetime.fromtimestamp(t0, timezone.utc):%H:%M:%S} -> "
              f"{datetime.fromtimestamp(t1, timezone.utc):%H:%M:%S} UTC | {SETS[tipo]}")
        if a.listar:
            continue
        outdir = os.path.join("graficos", name)
        os.makedirs(outdir, exist_ok=True)
        for qid in SETS[tipo]:
            try:
                msg = plot_one(qid, a.rate, t0, t1, marks, alerts, outdir, name)
            except Exception as e:
                msg = f"ERRO       {qid}: {e}"
            print("  " + msg)
            index.append(f"{name}\t{msg}")
    if not a.listar:
        with open("graficos/_index.txt", "w") as f:
            f.write("\n".join(index) + "\n")
        print("\n[info] resumo em graficos/_index.txt")


if __name__ == "__main__":
    main()