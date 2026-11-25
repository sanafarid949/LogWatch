import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Settings (inhein apni zaroorat se badlein)
FAIL_LIMIT = 5                  # itne failed logins = brute force
SPRAY_USERS = 4                 # itne alag users = password spraying
WINDOW = timedelta(minutes=5)   # time window
NIGHT_START, NIGHT_END = 0, 6   # raat 12 se subah 6
HUMAN_TYPES = {"2", "3", "7", "10", "11"}  # service/system logons ignore


def load_events(path):
    events = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row["Time"] = datetime.fromisoformat(row["Time"])
            events.append(row)
    return sorted(events, key=lambda e: e["Time"])


def analyze(events):
    alerts = []
    fails = defaultdict(list)   # source -> [(time, user)]
    seen = set()                # ek hi alert baar baar na aaye

    def alert(key, level, time, message):
        if key not in seen:
            seen.add(key)
            alerts.append((level, time, message))

    for e in events:
        t, user, ip = e["Time"], e["User"].lower(), e["IP"].strip()
        source = ip if ip not in ("", "-") else "local"

        # Sirf window ke andar wali failures rakho
        recent = [x for x in fails[source] if t - x[0] <= WINDOW]
        fails[source] = recent
        if not recent:  # purana attack khatam, naye par dobara alert
            seen -= {k for k in seen if k[1] == source}

        if e["EventID"] == "4625":
            recent.append((t, user))
            if len(recent) >= FAIL_LIMIT:
                alert(("brute", source), "HIGH", t,
                      f"Brute force: {len(recent)} failed logins from {source}")
            users = {u for _, u in recent}
            if len(users) >= SPRAY_USERS:
                alert(("spray", source), "HIGH", t,
                      f"Password spraying: {len(users)} users tried from {source}")

        elif e["EventID"] == "4624":
            if e["LogonType"] not in HUMAN_TYPES or user.endswith("$") \
                    or user in ("system", "anonymous logon"):
                continue
            if len(recent) >= FAIL_LIMIT:
                alert(("success", source, user), "CRITICAL", t,
                      f"Login SUCCESS after {len(recent)} failures: {user} from {source}")
            if NIGHT_START <= t.hour < NIGHT_END:
                alert(("night", source, user, t.date()), "MEDIUM", t,
                      f"Off-hours login: {user} from {source}")

        elif e["EventID"] == "4740":
            alert(("lock", source, user, t), "HIGH", t, f"Account locked: {user}")

    return alerts


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "events.csv"
    events = load_events(path)
    alerts = analyze(events)

    print(f"LogWatch: {len(events)} events checked, {len(alerts)} alerts\n")
    for level, time, message in alerts:
        print(f"[{level:8}] {time:%Y-%m-%d %H:%M:%S}  {message}")

    with open("report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Time", "Alert"])
        writer.writerows(alerts)
    print("\nReport saved: report.csv")


if __name__ == "__main__":
    main()