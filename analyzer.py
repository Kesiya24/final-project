import os
import re
from datetime import datetime

PACKETS_FILE = "packets.txt"
LOG_FILE = "logs/log.txt"

# Real attack indicators (process / tool names)
SUSPICIOUS_KEYWORDS = [
    "nc",
    "netcat",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "mshta",
    "mshta.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe"
]


def write_log(msg):
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")


def analyze_packets():
    alerts = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    write_log("=" * 60)
    write_log(f"Packet Analysis Started : {now}")

    if not os.path.exists(PACKETS_FILE):
        write_log("ERROR: packets.txt not found")
        return {
            "status": "error",
            "message": "packets.txt not found",
            "alerts": []
        }

    # pktmon output is UTF-16
    with open(PACKETS_FILE, encoding="utf-16", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        lower = line.lower()

        for indicator in SUSPICIOUS_KEYWORDS:
            # ✅ STRICT WORD-BOUNDARY MATCH
            # Matches: nc , nc.exe
            # Rejects: component, appearance
            pattern = rf"(?<![a-z0-9]){re.escape(indicator)}(\.exe)?(?![a-z0-9])"

            if re.search(pattern, lower):
                alert = {
                    "indicator": indicator,
                    "packet": line.strip(),
                    "time": now
                }

                alerts.append(alert)
                write_log(f"[SUSPICIOUS] {line.strip()}")
                break

    if not alerts:
        write_log("No suspicious activity found.")
        status = "clean"
        message = "No suspicious activity found"
    else:
        status = "alert"
        message = "Suspicious activity detected"

    write_log(f"Packet Analysis Ended   : {datetime.now()}")
    write_log("=" * 60)

    return {
        "status": status,
        "message": message,
        "alerts": alerts
    }
