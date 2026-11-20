#!/usr/bin/env python3
"""
resumo_corridas.py (v2) - uma linha por corrida de evidencias/, com os dados de TODAS as fontes,
cada coluna com a sua origem no nome. Nunca inventa: se uma fonte nao cobre a corrida, escreve n/d.

Uso (na raiz de P1, com o venv ativo):
  python3 monitoring/resumo_corridas.py
  python3 monitoring/resumo_corridas.py --arquivo                          # inclui _arquivo/ e _invalidas/
  python3 monitoring/resumo_corridas.py --db evidencias/_db/temp_data.db   # contagem na SQLite

Saidas: evidencias/_resumo.csv (todas as colunas) e evidencias/_resumo.md (tabelas por ameaca).

Fontes (prefixo/sufixo da coluna):
  (sem sufixo)  meta.txt, attacker_output.txt, access.log (evidencias/_logs), alertas Wazuh (evidencias/_wazuh)
  srv_*         access.log: contagens exatas. Registry e Ingestion avaliados em separado (cada log pode nao cobrir)
  _prom         ssle_report_w*.json -> ESTIMATIVA do Prometheus, nao usar como contagem
  _csv          graficos/<corrida>/*.csv -> janela do rate() por confirmar (omissao do graficos.py: 1m)
  sqlite_*      so com --db: linhas da SQLite com timestamp em [at - largura, at] (assume timestamps em UTC)
                sqlite_linhas_48 / sqlite_disp_48: linhas e device_id distintos com source_ip do atacante
                sqlite_leg_*: linhas dos sensores legitimos (source_ip diferente) e instante da ultima (s desde start)
  razao_*       Prometheus / log (so onde ambos existem). Serve para quantificar o vies, nao para contar.
  att_storage_acum  "Registos Botnet encontrados" do atacante: pode ser CUMULATIVO da base, nao usar como contagem da corrida

Convencoes: tempos 's' = segundos desde o start do meta.txt. Alertas Wazuh: ARREDONDADOS ao segundo (como as
legendas do graficos.py). Instantes do access.log: segundo inteiro (o log nao tem milissegundos).
Janela = [at - largura, at], com at = at_epoch ou start + offset (como verify.py/graficos.py).
"""
import argparse, ast, bisect, calendar, csv, glob, json, math, os, re, sqlite3, time
from collections import Counter, defaultdict
from datetime import datetime, timezone

ATT_IP = "10.255.255.48"
OFFSET = {"dos": 130, "normal": 130, "botnet": 70, "hijack": 70}
WIN = {"dos": 150, "normal": 150, "botnet": 90, "hijack": 90}
IDS = ("100201", "100211", "100220", "651", "652")
ND = "n/d"
RX = re.compile(r'^(\S+) - - \[(\d+/\w+/\d+ \d+:\d+:\d+)\] "(?:\x1b\[[0-9;]*m)*(\w+) (\S+) HTTP/[\d.]+(?:\x1b\[[0-9;]*m)*" (\d+)')

COLS = [
    "corrida", "tipo", "start", "end", "dur_s", "at_epoch", "janela_usada_s", "meta_window_s",
    "att_pedidos", "att_dur_s", "att_enviados_reg", "att_enviados_ing", "att_connect_timeout",
    "att_erros", "att_codigos", "att_fases", "att_storage_acum",
    "log_cobre_reg", "log_cobre_ing",
    "srv_48_reg", "srv_48_ing", "srv_48_ing_200", "srv_reg_total", "srv_ing_total", "srv_ing_5xx",
    "srv_primeiro_5xx_s", "srv_leg_ing", "srv_leg_200", "srv_leg_5xx", "srv_leg_ultimo_200_s", "srv_rajadas_48",
    "bloq_esperado", "bloq_visto",
    "wazuh_cobre", "w_100201_s", "w_100211_s", "w_100220_s", "w_651", "w_652", "w_eventos",
    "sqlite_linhas_48", "sqlite_disp_48", "sqlite_leg_linhas", "sqlite_leg_ultima_s",
    "cpu_ing_max_prom", "cpu_sto_max_prom", "ing_req_prom", "ing_5xx_prom", "ing_pico45s_prom",
    "ing_p95_prom", "reg_posts_prom", "sensor_regs_prom", "unique_dev_prom", "overwrites_prom",
    "razao_reg_prom_log", "razao_ing_prom_log",
    "cpu_ing_max_csv", "cpu_sto_max_csv", "pico_rate_csv", "p95_max_csv", "unique_dev_max_csv",
    "flags",
]

MD_COLS = {
    "normal": ["corrida", "dur_s", "srv_ing_total", "srv_leg_200", "srv_leg_5xx", "srv_reg_total",
               "sqlite_leg_linhas", "w_eventos", "cpu_ing_max_csv", "p95_max_csv", "unique_dev_max_csv", "flags"],
    "dos": ["corrida", "dur_s", "att_pedidos", "att_enviados_ing", "att_connect_timeout", "srv_48_ing",
            "srv_48_ing_200", "sqlite_linhas_48", "bloq_esperado", "srv_ing_5xx", "srv_primeiro_5xx_s",
            "srv_leg_ing", "srv_leg_200", "srv_rajadas_48", "w_eventos", "cpu_ing_max_csv",
            "cpu_sto_max_csv", "pico_rate_csv", "p95_max_csv", "flags"],
    "botnet": ["corrida", "dur_s", "att_enviados_reg", "att_enviados_ing", "att_connect_timeout",
               "srv_48_reg", "srv_48_ing", "bloq_esperado", "sqlite_linhas_48", "sqlite_disp_48",
               "unique_dev_prom", "unique_dev_max_csv", "reg_posts_prom", "razao_reg_prom_log",
               "w_eventos", "flags"],
    "hijack": ["corrida", "dur_s", "srv_ing_total", "srv_leg_200", "srv_ing_5xx", "srv_primeiro_5xx_s",
               "srv_leg_ultimo_200_s", "sqlite_leg_linhas", "sqlite_leg_ultima_s", "w_100220_s",
               "w_eventos", "overwrites_prom", "flags"],
}


# ---------------------------------------------------------------- leitura das fontes
def load_log(path):
    ev = []
    if not os.path.isfile(path):
        return [], []
    for line in open(path, errors="replace"):
        m = RX.match(line)
        if not m:
            continue
        ip, ts, meth, url, st = m.groups()
        try:
            t = calendar.timegm(time.strptime(ts, "%d/%b/%Y %H:%M:%S"))
        except ValueError:
            continue
        ev.append((t, ip, meth, url, st))
    ev.sort(key=lambda e: e[0])
    return ev, [e[0] for e in ev]


def win(ev, times, t0, t1):
    return ev[bisect.bisect_left(times, t0):bisect.bisect_right(times, t1)]


def covers(times, t0, t1):
    return bool(times) and times[0] <= t0 and times[-1] >= t1


def load_alerts(root):
    seen, ev, allts = set(), [], []
    for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
        for line in open(f, errors="replace"):
            try:
                a = json.loads(line)
                ts = a["timestamp"]
                t = datetime.fromisoformat(ts.replace("+0000", "+00:00")).timestamp()
            except Exception:
                continue
            allts.append(t)
            rid = str(a.get("rule", {}).get("id", ""))
            if rid in IDS:
                ag = a.get("agent", {}).get("name", "")
                key = (ts, rid, ag)
                if key in seen:
                    continue
                seen.add(key)
                ev.append((t, rid, ag))
    ev.sort()
    allts.sort()
    return ev, allts


def read_meta(d):
    p = os.path.join(d, "meta.txt")
    if not os.path.isfile(p):
        return None
    m = {}
    for line in open(p):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            m[k] = v
    return m


def parse_attacker(path):
    if not os.path.isfile(path):
        return None
    txt = open(path, errors="replace").read()
    out = {}
    for key, rx in (("fases", r"Fases:\s*(\{.*\})"), ("erros", r"Erros:\s*(\{.*\})"),
                    ("codigos", r"Códigos HTTP:\s*(\{.*\})")):
        m = re.search(rx, txt)
        try:
            out[key] = ast.literal_eval(m.group(1)) if m else None
        except Exception:
            out[key] = None
    for key, rx in (("dur", r"Duração:\s*([\d.]+)"), ("pedidos", r"Pedidos:\s*(\d+)"),
                    ("botnet_storage", r"Registos Botnet encontrados:\s*(\d+)")):
        m = re.search(rx, txt)
        out[key] = m.group(1) if m else None
    return out


def prom_json(d, w):
    p = os.path.join(d, f"ssle_report_w{w}.json")
    if os.path.isfile(p):
        try:
            return json.load(open(p))
        except Exception:
            return None
    return None


def csv_max(path, start, summed=False):
    if not os.path.isfile(path):
        return None
    tot = defaultdict(float)
    for r in csv.DictReader(open(path)):
        try:
            t = datetime.fromisoformat(r["time_utc"]).timestamp()
            v = float(r["valor"])
        except Exception:
            continue
        if t < start or v != v:
            continue
        if summed:
            tot[t] += v
        else:
            tot[(t, r["serie"])] = v
    return max(tot.values()) if tot else None


# ---------------------------------------------------------------- calculos por corrida
def fmt(v, nd=2):
    if v is None:
        return ND
    if isinstance(v, float):
        return f"{v:.{nd}f}".rstrip("0").rstrip(".") if nd else f"{v:.0f}"
    return str(v)


def ratio(a, b):
    try:
        a, b = float(a), float(b)
    except (TypeError, ValueError):
        return ND
    return f"{a / b:.2f}" if b else ND


def server_stats(reg_w, ing_w, start):
    """reg_w / ing_w: eventos da janela, ou None se o respetivo log nao cobre a janela."""
    s = {}
    if reg_w is not None:
        a_reg = [e for e in reg_w if e[2] == "POST" and e[3] == "/register"]
        s["srv_reg_total"] = len(a_reg)
        s["srv_48_reg"] = sum(1 for e in a_reg if e[1] == ATT_IP)
    if ing_w is not None:
        a_ing = [e for e in ing_w if e[2] == "POST" and e[3] == "/ingest"]
        s["srv_ing_total"] = len(a_ing)
        s["srv_48_ing"] = sum(1 for e in a_ing if e[1] == ATT_IP)
        s["srv_48_ing_200"] = sum(1 for e in a_ing if e[1] == ATT_IP and e[4] == "200")
        five = [e for e in a_ing if e[4].startswith("5")]
        s["srv_ing_5xx"] = len(five)
        s["srv_primeiro_5xx_s"] = min(e[0] for e in five) - start if five else "nenhum"
        leg = [e for e in a_ing if e[1] != ATT_IP]
        s["srv_leg_ing"] = len(leg)
        s["srv_leg_200"] = sum(1 for e in leg if e[4] == "200")
        s["srv_leg_5xx"] = sum(1 for e in leg if e[4].startswith("5"))
        l200 = [e[0] for e in leg if e[4] == "200"]
        s["srv_leg_ultimo_200_s"] = max(l200) - start if l200 else "nenhum"
        secs = sorted(Counter(e[0] for e in a_ing if e[1] == ATT_IP).items())
        bursts, cur = [], None
        for t, n in secs:
            if cur and t - cur[1] < 5:
                cur[1] = t
                cur[2] += n
            else:
                cur = [t, t, n]
                bursts.append(cur)
        s["srv_rajadas_48"] = "; ".join(f"{b[0]-start:+d}..{b[1]-start:+d}s:{b[2]}" for b in bursts) or "nenhuma"
    return s


def wazuh_stats(alerts, allts, start, at):
    s = {}
    i = bisect.bisect_left(allts, start - 900)
    s["wazuh_cobre"] = "sim" if i < len(allts) and allts[i] <= at + 900 else "NAO (sem alertas nem ficheiro)"
    sel = [(int(round(t - start)), rid, ag) for t, rid, ag in alerts if start - 5 <= t <= at + 20]
    short = lambda ag: ag.split("-")[0][:3] if ag else "?"
    for rid, col in (("100201", "w_100201_s"), ("100211", "w_100211_s"), ("100220", "w_100220_s")):
        ts = [r for r, i_, a in sel if i_ == rid]
        s[col] = f"{min(ts):+d}" if ts else "-"
    for rid, col in (("651", "w_651"), ("652", "w_652")):
        s[col] = ", ".join(f"{short(a)}:{r:+d}" for r, i_, a in sel if i_ == rid) or "-"
    s["w_eventos"] = "; ".join(f"{r:+d} {i_}@{short(a)}" for r, i_, a in sel) or "-"
    return s


def prom_stats(j):
    s = {}
    if not j:
        return s
    inf = j.get("infrastructure", {})
    ing = inf.get("ingestion-pt-aveiro-dc1-r01-n02", {})
    sto = inf.get("storage-pt-aveiro-dc1-r02-n01", {})
    s["cpu_ing_max_prom"] = fmt(ing.get("cpu_max_percent"))
    s["cpu_sto_max_prom"] = fmt(sto.get("cpu_max_percent"))
    ex, bz = j.get("ingestion_extra", {}), j.get("business", {})
    s["ing_req_prom"] = fmt(ex.get("ingest_requests_window"), 1)
    s["ing_5xx_prom"] = fmt(ex.get("ingest_5xx_window"), 1)
    s["ing_pico45s_prom"] = fmt(ex.get("ingest_peak_rps_45s"))
    s["ing_p95_prom"] = fmt(j.get("services", {}).get("ingestion-pt-aveiro-dc1-r01-n02", {}).get("latency_p95_seconds"), 3)
    s["reg_posts_prom"] = fmt(bz.get("registry_register_requests_window"), 1)
    s["sensor_regs_prom"] = fmt(bz.get("sensor_registrations_window"), 1)
    s["unique_dev_prom"] = fmt(bz.get("storage_unique_devices"), 0)
    s["overwrites_prom"] = fmt(bz.get("registry_overwrites"), 0)
    return s


def csv_stats(name, tipo, start):
    g = os.path.join("graficos", name)
    s = {}
    s["cpu_ing_max_csv"] = fmt(csv_max(os.path.join(g, "A4_cpu_ingestion.csv"), start))
    s["cpu_sto_max_csv"] = fmt(csv_max(os.path.join(g, "A5_cpu_storage.csv"), start))
    rate_file = {"dos": "A1_ingest_por_status.csv", "normal": "A1_ingest_por_status.csv",
                 "botnet": "B5_ingest_total.csv", "hijack": "C1_ingest_por_status.csv"}[tipo]
    s["pico_rate_csv"] = fmt(csv_max(os.path.join(g, rate_file), start, summed=True))
    s["p95_max_csv"] = fmt(csv_max(os.path.join(g, "A2_ingest_p95.csv"), start, summed=True), 3)
    s["unique_dev_max_csv"] = fmt(csv_max(os.path.join(g, "B6_dispositivos_unicos.csv"), start), 0)
    return s


def sqlite_stats(conn, t0, start, at):
    f = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        n, d = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT device_id) FROM temperatures "
            "WHERE source_ip=? AND timestamp>=? AND timestamp<=?", (ATT_IP, f(t0), f(at))).fetchone()
        ln, lmax = conn.execute(
            "SELECT COUNT(*), MAX(timestamp) FROM temperatures "
            "WHERE source_ip<>? AND timestamp>=? AND timestamp<=?", (ATT_IP, f(t0), f(at))).fetchone()
        ult = ND
        if lmax:
            ult = int(calendar.timegm(time.strptime(str(lmax)[:19], "%Y-%m-%d %H:%M:%S")) - int(start))
        return {"sqlite_linhas_48": n, "sqlite_disp_48": d, "sqlite_leg_linhas": ln, "sqlite_leg_ultima_s": ult}
    except Exception as e:
        return {"sqlite_linhas_48": f"erro: {e}"}


# ---------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="evidencias/_logs")
    ap.add_argument("--wazuh", default="evidencias/_wazuh")
    ap.add_argument("--db", default=None, help="copia da SQLite do Storage (opcional)")
    ap.add_argument("--arquivo", action="store_true", help="inclui _arquivo/ e _invalidas/")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()

    reg_ev, reg_t = load_log(os.path.join(a.logs, "registry.log"))
    ing_ev, ing_t = load_log(os.path.join(a.logs, "ingestion.log"))
    alerts, allts = load_alerts(a.wazuh)
    conn = None
    avisos = []
    if a.db:
        conn = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
        try:
            mn, mx = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM temperatures").fetchone()
            avisos.append(f"SQLite: timestamps de {mn} a {mx} (o filtro assume UTC)")
        except Exception as e:
            avisos.append(f"SQLite: nao consegui ler a tabela temperatures ({e})")

    def span(times):
        if not times:
            return "vazio"
        f = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        return f"{f(times[0])} -> {f(times[-1])}"
    fontes = [f"registry.log: {len(reg_ev)} linhas, {span(reg_t)} UTC",
              f"ingestion.log: {len(ing_ev)} linhas, {span(ing_t)} UTC",
              f"alertas Wazuh (regras {', '.join(IDS)}): {len(alerts)} unicos; ficheiros cobrem {span(allts)} UTC"]

    dirs = [d for d in sorted(glob.glob("evidencias/*/")) if not os.path.basename(d.rstrip("/")).startswith("_")]
    if a.arquivo:
        dirs += sorted(glob.glob("evidencias/_arquivo/*/")) + sorted(glob.glob("evidencias/_invalidas/*/"))

    rows = []
    for d in dirs:
        base = os.path.basename(d.rstrip("/"))
        parent = os.path.basename(os.path.dirname(d.rstrip("/")))
        archived = parent.startswith("_")
        name = f"{parent}/{base}" if archived else base
        if a.only and base not in a.only:
            continue
        tipo = base.split("_")[0]
        meta = read_meta(d)
        if tipo not in WIN:
            continue
        if not meta or "start" not in meta:
            avisos.append(f"{name}: sem meta.txt/start valido (ignorada)")
            continue
        start = datetime.fromisoformat(meta["start"]).timestamp()
        has_at = "at_epoch" in meta
        at = float(meta["at_epoch"]) if has_at else start + OFFSET[tipo]
        w = WIN[tipo]
        t0 = at - w
        flags = []
        if not has_at:
            flags.append("AT_CALCULADO")
        if meta.get("label", base) != base:
            flags.append(f"LABEL_DIFERE({meta.get('label')})")
        if "corr" in base:
            flags.append("TENTATIVA_CORRELACAO?")
        if meta.get("window_s") and meta["window_s"] != str(w):
            flags.append(f"META_JANELA={meta['window_s']}(usada {w})")

        r = {c: ND for c in COLS}
        r.update({"corrida": name, "tipo": tipo, "start": meta["start"], "end": meta.get("end", ND),
                  "dur_s": meta.get("duration_s", ND), "at_epoch": f"{at:.0f}",
                  "janela_usada_s": w, "meta_window_s": meta.get("window_s", ND)})

        # atacante
        att = parse_attacker(os.path.join(d, "attacker_output.txt"))
        sent_reg = sent_ing = conn_to = None
        if att and att.get("fases") is not None:
            fs, er = att["fases"], att.get("erros") or {}
            sent_reg = fs.get("sensor_registration")
            sent_ing = fs.get("fake_temperature_injection", fs.get("ingestion"))
            conn_to = er.get("ConnectTimeout", 0)
            r.update({"att_pedidos": att["pedidos"] or ND, "att_dur_s": att["dur"] or ND,
                      "att_enviados_reg": fmt(sent_reg, 0), "att_enviados_ing": fmt(sent_ing, 0),
                      "att_connect_timeout": conn_to, "att_erros": json.dumps(er),
                      "att_codigos": json.dumps(att.get("codigos")), "att_fases": json.dumps(fs),
                      "att_storage_acum": att["botnet_storage"] or ND})
        else:
            flags.append("SEM_ATACANTE")

        # servidor: cada log avaliado em separado
        cov_reg, cov_ing = covers(reg_t, t0, at), covers(ing_t, t0, at)
        r["log_cobre_reg"], r["log_cobre_ing"] = ("sim" if cov_reg else "NAO"), ("sim" if cov_ing else "NAO")
        r.update(server_stats(win(reg_ev, reg_t, t0, at) if cov_reg else None,
                              win(ing_ev, ing_t, t0, at) if cov_ing else None, int(start)))
        if not cov_reg:
            flags.append("SEM_LOG_REG")
        if not cov_ing:
            flags.append("SEM_LOG_ING")
        if cov_reg and cov_ing and att and att.get("fases") is not None:
            sent_tot = (sent_reg or 0) + (sent_ing or 0)
            visto = r["srv_48_reg"] + r["srv_48_ing"]
            if sent_tot and conn_to is not None:
                r["bloq_esperado"] = sent_tot - conn_to
                r["bloq_visto"] = visto
                if abs((sent_tot - conn_to) - visto) > max(10, 0.05 * sent_tot):
                    flags.append("BLOQ?")
            if (sent_reg is not None and r["srv_48_reg"] > sent_reg) or \
                    (sent_ing is not None and r["srv_48_ing"] > sent_ing):
                flags.append("L48>ENV")

        # wazuh, prometheus, csv, sqlite
        r.update(wazuh_stats(alerts, allts, start, at))
        pj = prom_json(d, w)
        if pj is None:
            flags.append("SEM_JSON")
        else:
            r.update(prom_stats(pj))
            r["razao_reg_prom_log"] = ratio(r["reg_posts_prom"], r["srv_reg_total"])
            r["razao_ing_prom_log"] = ratio(r["ing_req_prom"], r["srv_ing_total"])
            ex = pj.get("ingestion_extra", {}).get("ingest_requests_window")
            if cov_ing and ex is not None and isinstance(r["srv_ing_total"], int):
                lt = r["srv_ing_total"]
                if abs(ex - lt) > 5 and abs(ex - lt) / max(lt, 1) > 0.10:
                    flags.append(f"PROM_ING({ex - lt:+.0f})")
        if not archived:   # os CSV de graficos/ so existem para as corridas principais
            r.update(csv_stats(base, tipo, start))
        if conn:
            r.update(sqlite_stats(conn, t0, start, at))
            if isinstance(r["sqlite_linhas_48"], int) and isinstance(r["srv_48_ing_200"], int) \
                    and r["sqlite_linhas_48"] != r["srv_48_ing_200"]:
                flags.append(f"SQLITE!=LOG200({r['sqlite_linhas_48']}/{r['srv_48_ing_200']})")
        r["flags"] = " ".join(flags) or "-"
        rows.append(r)

    # saidas
    os.makedirs("evidencias", exist_ok=True)
    with open("evidencias/_resumo.csv", "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=COLS)
        wr.writeheader()
        wr.writerows(rows)

    def md_table(rs, cols):
        out = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
        for r in rs:
            out.append("| " + " | ".join(str(r.get(c, ND)).replace("|", "/") for c in cols) + " |")
        return "\n".join(out)

    md = ["# Resumo das corridas", "",
          f"Gerado em {datetime.now().isoformat(timespec='seconds')}. Tempos `_s` = segundos desde o start do meta.txt (alertas Wazuh arredondados; access.log com resolucao de 1 s).",
          "Sufixo `_prom` = estimativa do Prometheus (nao e contagem). Sufixo `_csv` = CSV de graficos/ (janela do rate() por confirmar).",
          "`srv_*` = access.log (contagens exatas; Registry e Ingestion avaliados em separado). `sqlite_*` = copia da base (so com --db). `n/d` = fonte sem dados para esta corrida.", "",
          "## Fontes", ""] + [f"- {x}" for x in fontes] + [""]
    for tipo in ("normal", "dos", "botnet", "hijack"):
        rs = [r for r in rows if r["tipo"] == tipo]
        if rs:
            md += [f"## {tipo}", "", md_table(rs, MD_COLS[tipo]), ""]
    for r in rows:
        if r["flags"] != "-":
            avisos.append(f"{r['corrida']}: {r['flags']}")
    md += ["## Avisos", ""] + [f"- {x}" for x in avisos] + [""]
    with open("evidencias/_resumo.md", "w") as f:
        f.write("\n".join(md))
    print(f"[ok] {len(rows)} corridas -> evidencias/_resumo.csv e evidencias/_resumo.md")
    for x in avisos:
        print("[aviso]", x)


if __name__ == "__main__":
    main()
