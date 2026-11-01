import csv
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

YEAR = 2026                      # syslog has no year; assumed (see README)
THRESHOLD = 5
WINDOW = timedelta(minutes=10)

LINE = re.compile(
    r"^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(Failed|Accepted) password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)

def parse_line(line):
    m = LINE.match(line) #checks for the regex pattern defined in LINE
    if not m:
        return None
    ts_text, result, user, ip = m.groups() #stores timestamp text, whether the password was accepted or not, username and ip in a group
    ts = datetime.strptime(f"{YEAR} {ts_text}", "%Y %b %d %H:%M:%S")
    return {"ts": ts, "success": result == "Accepted", "user": user, "ip": ip}

def load_events(path):
    events = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e:
                events.append(e) #stores result returned by parse(line) in event
    return events

def find_bruteforce(events, threshold, window):
    fails = defaultdict(list)
    for e in events:
        if not e["success"]:
            fails[e["ip"]].append(e["ts"])
    flagged = {}
    for ip, times in fails.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 >= threshold:
                flagged[ip] = times[end]
                break
    return flagged, fails

def build_rows(events, flagged, fails):
    rows = []
    for ip, burst_ts in flagged.items():
        times = fails[ip]
        later = [e for e in events
                 if e["ip"] == ip and e["success"] and e["ts"] >= burst_ts]
        rows.append({
            "ip": ip,
            "failure_count": len(times),
            "first_seen": times[0],
            "last_seen": times[-1],
            "burst_detected_at": burst_ts,
            "success_after_burst": bool(later),
            "compromised_user": later[0]["user"] if later else "",
        })
    return rows

def write_csv(rows, path):
    fields = ["ip", "failure_count", "first_seen", "last_seen",
              "burst_detected_at", "success_after_burst", "compromised_user"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/log_parser.py <logfile>")
        return
    events = load_events(sys.argv[1])
    print(len(events), "events parsed")
    flagged, fails = find_bruteforce(events, THRESHOLD, WINDOW)
    rows = build_rows(events, flagged, fails)
    write_csv(rows, "flagged_ips.csv")
    print(f"{len(rows)} flagged IPs written to flagged_ips.csv")
    for r in rows:
        if r["success_after_burst"]:
            print(f"HIGH: {r['ip']} logged in as '{r['compromised_user']}' after a brute-force burst")

if __name__ == "__main__":
    main()