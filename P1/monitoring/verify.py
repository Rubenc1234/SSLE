#!/usr/bin/env python3
"""
verify.py - validacao cruzada, uma linha por corrida, entre 3 fontes independentes:
  (1) o que o atacante diz que enviou     -> evidencias/<corrida>/attacker_output.txt
  (2) o que o servidor realmente recebeu    -> access.log do Registry e do Ingestion
  (3) o que o Prometheus estimou            -> evidencias/<corrida>/ssle_report_w90|w150.json

Uso (na raiz de P1):
  incus file pull $REGISTRY/var/log/ssle/access.log  /tmp/logs/registry.log
  incus file pull $INGESTION/var/log/ssle/access.log /tmp/logs/ingestion.log
  python3 monitoring/verify.py               # todas as corridas validas
  python3 monitoring/verify.py --only dos_r2    # uma ou varias
  python3 monitoring/verify.py --logs evidencias/_logs

Janela por corrida: igual ao reprocess.sh (at_epoch do meta.txt, ou start+70/130;
largura 90 s botnet/hijack, 150 s dos/normal). Resultado tambem em evidencias/_verificacao.txt

Flags:
  SEM_LOG       o log nao cobre a janela da corrida (log antigo, limpo ou nao descarregado)
  SEM_JSON      nao existe o ssle_report_w*.json (corre reprocess.sh)
  PROM_ING      Prometheus difere >10% (e >5 pedidos) do log nos /ingest totais
  PROM_REG      idem para os /register totais
  L48>ENV       o log viu mais pedidos do atacante do que ele diz ter enviado (nao devia acontecer)
  BLOQ?         enviados - ConnectTimeout nao bate com o que o servidor viu do atacante (+-5%/10)
Uma flag e um sinal para investigar, nao prova de erro.
"""
import argparse, ast, calendar, glob, json, os, re, time
from datetime import datetime

ATT_IP = "10.255.255.48"
OFFSET = {"dos": 130, "normal": 130, "botnet": 70, "hijack": 70}
WIN = {"dos": 150, "normal": 150, "botnet": 90, "hijack": 90}
RX = re.compile(r'^(\S+) - - \[(\d+/\w+/\d+ \d+:\d+:\d+)\] "(?:\x1b\[[0-9;]*m)*(\w+) (\S+) HTTP/[\d.]+(?:\x1b\[[0-9;]*m)*" (\d+)')


def load_log(path):
    ev = []
    if not os.path.isfile(path):
        return ev
    for line in open(path, errors="replace"):
        m = RX.match(line)
        if m:
            ip, ts, meth, url, st = m.groups()
            ev.append((calendar.timegm(time.strptime(ts, "%d/%b/%Y %H:%M:%S")), ip, meth, url, st))
    return ev


def covers(ev, t0, t1):
    return bool(ev) and ev[0][0] <= t0 and ev[-1][0] >= t1


def count(ev, t0, t1, url, ip=None, five=False):
    n = 0
    for t, i, meth, u, st in ev:
        if t0 <= t <= t1 and meth == "POST" and u == url:
            if ip and i != ip:
                continue
            if five and not st.startswith("5"):
                continue
            n += 1
    return n


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
    for key, rx in (("fases", r"Fases:\s*(\{.*\})"), ("erros", r"Erros:\s*(\{.*\})")):
        m = re.search(rx, txt)
        try:
            out[key] = ast.literal_eval(m.group(1)) if m else None
        except Exception:
            out[key] = None
    return out if out.get("fases") is not None else None


def prom(d, w):
    p = os.path.join(d, f"ssle_report_w{w}.json")
    if not os.path.isfile(p):
        return None
    j = json.load(open(p))
    return {
        "ing": j.get("ingestion_extra", {}).get("ingest_requests_window"),
        "ing5": j.get("ingestion_extra", {}).get("ingest_5xx_window"),
        "reg": j.get("business", {}).get("registry_register_requests_window"),
    }


def f0(v):
    return "  -" if v is None else f"{v:.0f}"


def diverge(p, l):
    return p is not None and abs(p - l) > 5 and abs(p - l) / max(l, 1) > 0.10


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--logs", default="/tmp/logs")
    a = ap.parse_args()

    reg_ev = load_log(os.path.join(a.logs, "registry.log"))
    ing_ev = load_log(os.path.join(a.logs, "ingestion.log"))
    print(f"[info] logs: registry={len(reg_ev)} linhas, ingestion={len(ing_ev)} linhas (pasta {a.logs})")

    hdr = (f"{'corrida':26} {'env reg/ing':>11} {'ConnTO':>6} | {'.48 reg/ing':>11} | "
           f"{'ing log':>7} {'ing prom':>8} {'d%':>5} | {'reg log':>7} {'reg prom':>8} | {'5xx log/prom':>12} | flags")
    lines = [hdr, "-" * len(hdr)]
    for d in sorted(glob.glob("evidencias/*/")):
        name = os.path.basename(d.rstrip("/"))
        if name.startswith("_") or (a.only and name not in a.only):
            continue
        tipo = name.split("_")[0]
        meta = read_meta(d)
        if tipo not in WIN or not meta or "start" not in meta:
            continue
        start = datetime.fromisoformat(meta["start"]).timestamp()
        at = float(meta["at_epoch"]) if "at_epoch" in meta else start + OFFSET[tipo]
        w = WIN[tipo]
        t0, t1 = at - w, at
        flags = []

        att = parse_attacker(os.path.join(d, "attacker_output.txt"))
        sent_reg = sent_ing = conn = None
        if att:
            fs, er = att["fases"], att.get("erros") or {}
            sent_reg = fs.get("sensor_registration")
            sent_ing = fs.get("fake_temperature_injection", fs.get("ingestion"))
            conn = er.get("ConnectTimeout", 0)

        if not (covers(reg_ev, t0, t1) and covers(ing_ev, t0, t1)):
            flags.append("SEM_LOG")
        l48_reg = count(reg_ev, t0, t1, "/register", ATT_IP)
        l48_ing = count(ing_ev, t0, t1, "/ingest", ATT_IP)
        lt_reg = count(reg_ev, t0, t1, "/register")
        lt_ing = count(ing_ev, t0, t1, "/ingest")
        l5 = count(ing_ev, t0, t1, "/ingest", five=True)

        p = prom(d, w)
        if p is None:
            flags.append("SEM_JSON")
        else:
            if "SEM_LOG" not in flags:
                if diverge(p["ing"], lt_ing):
                    flags.append("PROM_ING")
                if diverge(p["reg"], lt_reg):
                    flags.append("PROM_REG")
        if "SEM_LOG" not in flags and att:
            if (sent_reg is not None and l48_reg > sent_reg) or (sent_ing is not None and l48_ing > sent_ing):
                flags.append("L48>ENV")
            sent_tot = (sent_reg or 0) + (sent_ing or 0)
            if sent_tot and conn is not None:
                if abs((sent_tot - conn) - (l48_reg + l48_ing)) > max(10, 0.05 * sent_tot):
                    flags.append("BLOQ?")

        dpct = ""
        if p and p["ing"] is not None and lt_ing:
            dpct = f"{(p['ing'] - lt_ing) / lt_ing * 100:+.0f}"
        env = f"{f0(sent_reg)}/{f0(sent_ing)}" if att else "  -"
        lines.append(
            f"{name:26} {env:>11} {f0(conn) if att else '  -':>6} | {f'{l48_reg}/{l48_ing}':>11} | "
            f"{lt_ing:>7} {f0(p['ing']) if p else '  -':>8} {dpct:>5} | {lt_reg:>7} {f0(p['reg']) if p else '  -':>8} | "
            f"{f'{l5}/' + f0(p['ing5']) if p else f'{l5}/-':>12} | {' '.join(flags)}")

    out = "\n".join(lines)
    print(out)
    with open("evidencias/_verificacao.txt", "w") as f:
        f.write(out + "\n")
    print("\n[info] guardado em evidencias/_verificacao.txt")


if __name__ == "__main__":
    main()
