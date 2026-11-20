"""Access-log statistics (nginx 'combined' format) and log tailing. Standard library only."""
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime

LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def parse_time(s):
    # 20/Nov/2026:08:34:12 -0600
    try:
        d, rest = s.split(":", 1)
        day, mon, year = d.split("/")
        hms, tz = rest.split(" ")
        h, mi, se = hms.split(":")
        sign = 1 if tz[0] == "+" else -1
        off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        dt = datetime(int(year), MONTHS[mon], int(day), int(h), int(mi), int(se))
        return (dt - datetime(1970, 1, 1)).total_seconds() - off
    except Exception:
        return None


def tail_bytes(path, max_bytes):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()  # drop partial line
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def tail_lines(path, lines=200, query=None, max_bytes=8 * 1024 * 1024):
    text = tail_bytes(path, max_bytes)
    rows = text.splitlines()
    if query:
        q = query.lower()
        rows = [r for r in rows if q in r.lower()]
    return rows[-lines:]


def read_window(path, since, max_bytes=16 * 1024 * 1024):
    """Return parsed entries newer than `since` (epoch seconds)."""
    out = []
    for line in tail_bytes(path, max_bytes).splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        t = parse_time(m.group("time"))
        if t is None or t < since:
            continue
        req = m.group("req").split(" ")
        out.append({
            "t": t, "ip": m.group("ip"), "status": int(m.group("status")),
            "bytes": int(m.group("bytes")) if m.group("bytes") != "-" else 0,
            "method": req[0] if len(req) > 1 else "-",
            "path": (req[1] if len(req) > 1 else m.group("req"))[:200],
            "ua": (m.group("ua") or "")[:160],
        })
    return out


def summarize(paths, minutes=15, now=None):
    now = now or time.time()
    since = now - minutes * 60
    bucket = 60 if minutes <= 180 else 600
    nb = int(minutes * 60 // bucket)
    start = now - nb * bucket
    timeline = [{"t": start + i * bucket, "total": 0, "c4": 0, "c5": 0} for i in range(nb)]
    statuses, classes = Counter(), Counter()
    ips, paths_c, uas = Counter(), Counter(), Counter()
    per_log = defaultdict(int)
    total = 0
    nbytes = 0
    for p in paths:
        for e in read_window(p, since):
            total += 1
            nbytes += e["bytes"]
            per_log[os.path.basename(p)] += 1
            statuses[e["status"]] += 1
            cls = f"{e['status'] // 100}xx"
            classes[cls] += 1
            ips[e["ip"]] += 1
            paths_c[e["path"].split("?")[0]] += 1
            if e["ua"]:
                uas[e["ua"]] += 1
            i = int((e["t"] - start) // bucket)
            if 0 <= i < nb:
                timeline[i]["total"] += 1
                if e["status"] >= 500:
                    timeline[i]["c5"] += 1
                elif e["status"] >= 400:
                    timeline[i]["c4"] += 1
    return {
        "minutes": minutes, "bucket": bucket, "total": total, "bytes": nbytes,
        "rpm": round(total / max(minutes, 1), 2),
        "timeline": timeline,
        "classes": dict(classes),
        "statuses": statuses.most_common(12),
        "top_ips": ips.most_common(10),
        "top_paths": paths_c.most_common(10),
        "top_agents": uas.most_common(6),
        "per_log": dict(per_log),
    }


def count_recent(path, minutes=5):
    return len(read_window(path, time.time() - minutes * 60, max_bytes=4 * 1024 * 1024))


def parse_stub_status(text):
    m = re.search(r"Active connections:\s*(\d+)", text)
    m2 = re.search(r"\n\s*(\d+)\s+(\d+)\s+(\d+)\s*\n", text)
    m3 = re.search(r"Reading:\s*(\d+)\s*Writing:\s*(\d+)\s*Waiting:\s*(\d+)", text)
    if not m:
        return None
    out = {"active": int(m.group(1))}
    if m2:
        out.update(accepts=int(m2.group(1)), handled=int(m2.group(2)), requests=int(m2.group(3)))
    if m3:
        out.update(reading=int(m3.group(1)), writing=int(m3.group(2)), waiting=int(m3.group(3)))
    return out
