from flask import Flask, render_template, jsonify
import re
from collections import defaultdict
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
LOG_FILE = r"R:\Network_security\ids_alerts.log"

def parse_log():
    alerts = []
    attack_counts = defaultdict(int)
    blocked_ips = {}

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                alert_match = re.match(
                    r"\[(.+?)\] ALERT \| (.+?) \| SRC: (.+?) \| (.*)", line
                )
                if alert_match:
                    timestamp, attack_type, src_ip, detail = alert_match.groups()
                    alerts.append({
                        "time": timestamp,
                        "type": attack_type,
                        "src": src_ip,
                        "detail": detail
                    })
                    attack_counts[attack_type] += 1

                block_match = re.match(r"\[(.+?)\] BLOCKED \| IP: (.+)", line)
                if block_match:
                    timestamp, ip = block_match.groups()
                    if ip not in blocked_ips:
                        blocked_ips[ip] = {"ip": ip, "time": timestamp, "reasons": []}

    except FileNotFoundError:
        pass

    for alert in alerts:
        if alert["src"] in blocked_ips:
            reason = alert["type"]
            if reason not in blocked_ips[alert["src"]]["reasons"]:
                blocked_ips[alert["src"]]["reasons"].append(reason)

    return alerts, dict(attack_counts), list(blocked_ips.values())


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    alerts, attack_counts, blocked = parse_log()
    return jsonify({
        "total_alerts": len(alerts),
        "ips_blocked": len(blocked),
        "port_scans": attack_counts.get("Port Scan", 0),
        "attack_breakdown": attack_counts,
        "blocked_ips": blocked[-10:],
        "recent_alerts": alerts[-50:][::-1]
    })


@app.route("/api/geoip/<ip>")
def geoip(ip):
    try:
        res = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city",
            timeout=3
        )
        return jsonify(res.json())
    except:
        return jsonify({"country": "Unknown", "countryCode": "", "city": ""})


@app.route("/api/timeline")
def timeline():
    alerts, _, _ = parse_log()

    now = datetime.now()
    buckets = {}
    for i in range(20):
        minute = (now - timedelta(minutes=i)).strftime("%H:%M")
        buckets[minute] = 0

    for alert in alerts:
        try:
            dt = datetime.strptime(alert["time"], "%Y-%m-%d %H:%M:%S")
            minute = dt.strftime("%H:%M")
            if minute in buckets:
                buckets[minute] += 1
        except:
            pass

    labels = list(reversed(list(buckets.keys())))
    values = list(reversed(list(buckets.values())))
    return jsonify({"labels": labels, "values": values})


if __name__ == "__main__":
    print("[*] Dashboard running at http://127.0.0.1:5000")
    app.run(debug=False, port=5000)