import re, sys, time, calendar
from collections import Counter
log, at, w = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
events = "--events" in sys.argv
rx = re.compile(r'^(\S+) - - \[(\d+/\w+/\d+ \d+:\d+:\d+)\] "(?:\x1b\[[0-9;]*m)*(\w+) (\S+) HTTP/[\d.]+(?:\x1b\[[0-9;]*m)*" (\d+)')
c, sec = Counter(), Counter()
for line in open(log, errors="replace"):
    m = rx.match(line)
    if not m: continue
    ip, ts, meth, url, st = m.groups()
    t = calendar.timegm(time.strptime(ts, "%d/%b/%Y %H:%M:%S"))
    if not (at - w <= t <= at) or meth != "POST" or url not in ("/register", "/ingest"): continue
    c[(ip, url, st)] += 1
    if events and url == "/ingest" and st.startswith("5"): sec[time.strftime("%H:%M:%S", time.gmtime(t))] += 1
for k, v in sorted(c.items()): print(f"{k[0]:16} {k[1]:10} {k[2]} {v}")
if events: print("5xx por segundo:", dict(sorted(sec.items())))
