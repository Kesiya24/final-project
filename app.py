from flask import Flask, render_template, jsonify, send_file
import platform
import os
import json

from analyzer import analyze_packets
from capture_windows import capture_windows
from capture_linux import capture_linux

app = Flask(__name__)

LOG_FILE = "logs/log.txt"
PACKETS_FILE = "packets.txt"
RESULT_FILE = "results/detection_result.json"


def read_file(path, encoding="utf-8", max_chars=12000):
    if not os.path.exists(path):
        return "File not found"
    with open(path, encoding=encoding, errors="ignore") as f:
        return f.read(max_chars)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/scan")
def scan():
    os.makedirs("results", exist_ok=True)

    os_type = platform.system()

    if os_type == "Windows":
        success, msg = capture_windows()
    else:
        success, msg = capture_linux()

    if not success:
        return jsonify({
            "system": os_type,
            "status": "error",
            "message": msg,
            "alerts": [],
            "log_txt": read_file(LOG_FILE),
            "packets_txt": read_file(PACKETS_FILE, "utf-16")
        })

    result = analyze_packets()

    # Save detection result for download
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return jsonify({
        "system": os_type,
        "status": result["status"],
        "message": result["message"],
        "alerts": result["alerts"],
        "log_txt": read_file(LOG_FILE),
        "packets_txt": read_file(PACKETS_FILE, "utf-16")
    })


# 🔽 DOWNLOAD ROUTES
@app.route("/download/log")
def download_log():
    return send_file(LOG_FILE, as_attachment=True)


@app.route("/download/packets")
def download_packets():
    return send_file(PACKETS_FILE, as_attachment=True)


@app.route("/download/result")
def download_result():
    return send_file(RESULT_FILE, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
