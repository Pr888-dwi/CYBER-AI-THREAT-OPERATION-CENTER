from flask import Flask, jsonify, render_template_string, request  # type: ignore[reportMissingImports]
import os
import pickle
import sqlite3
import subprocess
import sys
from pathlib import Path
import numpy as np  # type: ignore[reportMissingImports]

try:
    import psutil
except ImportError:
    psutil = None

try:
    import xgboost as xgb
except ImportError:
    xgb = None

try:
    import lightgbm as lgb
except ImportError:
    lgb = None

try:
    from scapy.all import sniff, TCP, UDP  # type: ignore[reportMissingImports]
except ImportError:
    sniff = None
    TCP = None
    UDP = None
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
        from scapy.all import sniff, TCP, UDP  # type: ignore[reportMissingImports]
    except Exception:
        sniff = None
        TCP = None
        UDP = None

app = Flask(__name__)

DB_PATH = Path(__file__).resolve().parent / "cyberai.db"
MODEL_PATH = Path(__file__).resolve().parent / "threat_model_multi.pkl"

metrics_state = {
    "last_packet_count": 0,
    "last_capture_at": None,
}

HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CyberAI | Threat Operations Center</title>
    <style>
      :root {
        --bg: #0f172a;
        --panel: #111827;
        --panel-2: #1f2937;
        --text: #f8fafc;
        --accent: #f59e0b;
        --border: #334155;
      }
      body { font-family: Inter, Arial, sans-serif; margin: 0; background: radial-gradient(circle at top left, #1e293b, var(--bg)); color: var(--text); }
      .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
      .hero { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.3rem; }
      .card { background: linear-gradient(145deg, var(--panel), var(--panel-2)); border: 1px solid var(--border); border-radius: 16px; padding: 1rem 1.2rem; margin-bottom: 1rem; box-shadow: 0 10px 24px rgba(0,0,0,0.25); }
      .pill { display: inline-block; padding: 0.35rem 0.7rem; border-radius: 999px; background: linear-gradient(90deg, var(--accent), #fb923c); color: #111111; margin-right: 0.35rem; font-size: 0.85rem; font-weight: bold; }
      textarea, input, select { width: 100%; padding: 0.75rem; border-radius: 10px; border: 1px solid var(--border); background: #020617; color: var(--text); margin-top: 0.5rem; }
      button { padding: 0.8rem 1rem; border: none; border-radius: 10px; background: linear-gradient(90deg, var(--accent), #fb923c); color: #111111; cursor: pointer; font-weight: bold; }
      pre { white-space: pre-wrap; background: #020617; padding: 1rem; border-radius: 10px; border: 1px solid var(--border); color: #e2e8f0; }
      .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
      @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .hero { flex-direction: column; align-items: flex-start; } }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="hero">
        <div>
          <h1>CyberAI Threat Operations Center</h1>
          <p>Real-time detection, explanation, and response guidance for modern security teams.</p>
        </div>
        <div>
          <span class="pill">ML Detection</span>
          <span class="pill">Threat DB</span>
          <span class="pill">SOC Assistant</span>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h3>Analyze Traffic</h3>
          <textarea id="samples" rows="8">[{"src_port":52314,"dst_port":22,"bytes":1200,"duration":0.8},{"src_port":44321,"dst_port":445,"bytes":8500,"duration":3.2},{"src_port":60210,"dst_port":3389,"bytes":30000,"duration":1.5}]</textarea>
          <br><br>
          <button onclick="captureTraffic()">Capture Live Traffic</button>
          <button onclick="runAnalysis()">Analyze</button>
        </div>
        <div class="card">
          <h3>Threat Summary</h3>
          <pre id="result">Waiting for analysis...</pre>
        </div>
      </div>

      <div class="card">
        <h3>Ask the SOC Assistant</h3>
        <input id="question" placeholder="e.g. Why was this flagged?" />
        <br><br>
        <button onclick="askAssistant()">Ask</button>
        <pre id="answer">No question yet.</pre>
      </div>

      <div class="card">
        <h3>Real-Time Dashboard</h3>
        <div class="grid">
          <div class="card">
            <h4>Live Packet Count</h4>
            <canvas id="packetChart" height="180"></canvas>
          </div>
          <div class="card">
            <h4>Active Attacks</h4>
            <canvas id="attackChart" height="180"></canvas>
          </div>
          <div class="card">
            <h4>CPU Usage</h4>
            <canvas id="cpuChart" height="180"></canvas>
          </div>
          <div class="card">
            <h4>Threat Timeline</h4>
            <canvas id="timelineChart" height="180"></canvas>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>Runtime Status</h3>
        <pre id="runtime-status">Checking runtime...</pre>
      </div>

      <div class="card">
        <h3>Recent Alerts</h3>
        <button onclick="clearAlerts()">Clear History</button>
        <pre id="alerts">Loading alerts...</pre>
      </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      let packetChart, attackChart, cpuChart, timelineChart;
      function initCharts() {
        const packetCtx = document.getElementById('packetChart').getContext('2d');
        packetChart = new Chart(packetCtx, {
          type: 'bar',
          data: { labels: ['Packets'], datasets: [{ label: 'Packet Count', data: [0], backgroundColor: ['#f59e0b'] }] },
          options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });

        const attackCtx = document.getElementById('attackChart').getContext('2d');
        attackChart = new Chart(attackCtx, {
          type: 'doughnut',
          data: { labels: ['Active', 'Inactive'], datasets: [{ data: [0, 1], backgroundColor: ['#ef4444', '#64748b'] }] },
          options: { responsive: true }
        });

        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        cpuChart = new Chart(cpuCtx, {
          type: 'line',
          data: { labels: [], datasets: [{ label: 'CPU %', data: [], borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.2)', fill: true }] },
          options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } }
        });

        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        timelineChart = new Chart(timelineCtx, {
          type: 'line',
          data: { labels: [], datasets: [{ label: 'Threat Severity', data: [], borderColor: '#38bdf8', backgroundColor: 'rgba(56,189,248,0.2)', fill: true }] },
          options: { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } }
        });
      }

      async function runAnalysis() {
        const payload = { samples: JSON.parse(document.getElementById('samples').value) };
        const response = await fetch('/analyze', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
        const data = await response.json();
        document.getElementById('result').textContent = JSON.stringify(data, null, 2);
        loadAlerts();
      }
      async function askAssistant() {
        const question = document.getElementById('question').value;
        const response = await fetch('/ask', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ question, samples: JSON.parse(document.getElementById('samples').value) })});
        const data = await response.json();
        document.getElementById('answer').textContent = data.answer;
      }
      async function captureTraffic() {
        document.getElementById('result').textContent = 'Capturing live traffic...';
        const response = await fetch('/capture');
        const data = await response.json();
        if (!response.ok) {
          document.getElementById('result').textContent = data.error || 'Capture failed. Make sure scapy is installed and you have permission to capture traffic.';
          return;
        }
        document.getElementById('samples').value = JSON.stringify(data.samples, null, 2);
        document.getElementById('result').textContent = `Captured ${data.samples.length} packets. Click Analyze to process.`;
      }
      async function loadAlerts() {
        const response = await fetch('/alerts');
        const data = await response.json();
        document.getElementById('alerts').textContent = JSON.stringify(data, null, 2);
      }
      async function clearAlerts() {
        await fetch('/alerts/clear', { method: 'POST' });
        loadAlerts();
      }
      async function loadMetrics() {
        const response = await fetch('/metrics');
        const data = await response.json();
        packetChart.data.datasets[0].data = [data.packet_count];
        packetChart.update();
        attackChart.data.datasets[0].data = [data.active_attacks, Math.max(data.total_alerts - data.active_attacks, 0)];
        attackChart.update();
        if (cpuChart.data.labels.length >= 12) {
          cpuChart.data.labels.shift();
          cpuChart.data.datasets[0].data.shift();
        }
        cpuChart.data.labels.push(new Date().toLocaleTimeString());
        cpuChart.data.datasets[0].data.push(data.cpu_usage || 0);
        cpuChart.update();
        const timelineLabels = data.attack_timeline.map(item => item.time);
        const timelineValues = data.attack_timeline.map(item => item.severity);
        timelineChart.data.labels = timelineLabels;
        timelineChart.data.datasets[0].data = timelineValues;
        timelineChart.update();
      }
      async function loadStatus() {
        const response = await fetch('/status');
        const data = await response.json();
        document.getElementById('runtime-status').textContent = JSON.stringify(data, null, 2);
      }
      async function loadMetrics() {
        const response = await fetch('/metrics');
        const data = await response.json();
        packetChart.data.datasets[0].data = [data.packet_count];
        packetChart.update();
        attackChart.data.datasets[0].data = [data.active_attacks, Math.max(data.total_alerts - data.active_attacks, 0)];
        attackChart.update();
        if (cpuChart.data.labels.length >= 12) {
          cpuChart.data.labels.shift();
          cpuChart.data.datasets[0].data.shift();
        }
        const now = new Date().toLocaleTimeString();
        cpuChart.data.labels.push(now);
        cpuChart.data.datasets[0].data.push(data.cpu_usage || 0);
        cpuChart.update();
        const timelineLabels = data.attack_timeline.map(item => item.time);
        const timelineValues = data.attack_timeline.map(item => item.severity);
        timelineChart.data.labels = timelineLabels;
        timelineChart.data.datasets[0].data = timelineValues;
        timelineChart.update();
      }
      initCharts();
      loadAlerts();
      loadStatus();
      loadMetrics();
      setInterval(() => { loadMetrics(); loadStatus(); }, 3000);
    </script>
  </body>
</html>
"""


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            risk TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def train_model_if_needed():
    if MODEL_PATH.exists():
        return

    X = np.array([
        [0.1, 0.1, 0.0, 0.0],
        [0.2, 0.2, 0.0, 0.0],
        [0.3, 0.3, 1.0, 0.0],
        [0.8, 0.7, 1.0, 1.0],
        [0.9, 0.8, 1.0, 1.0],
        [0.4, 0.4, 0.0, 0.0],
        [0.95, 0.9, 1.0, 1.0],
        [0.5, 0.6, 1.0, 0.0],
        [0.25, 0.8, 0.0, 0.0],
        [0.1, 0.7, 1.0, 0.0],
        [0.05, 0.2, 0.0, 1.0],
        [0.4, 0.9, 1.0, 1.0],
    ])
    y = np.array([
        "Normal",
        "Normal",
        "Port Scan",
        "Brute Force",
        "DDoS",
        "Normal",
        "Botnet",
        "Ransomware",
        "SQL Injection",
        "Data Exfiltration",
        "Malware",
        "Brute Force",
    ])

    if xgb is not None:
        model = xgb.XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', verbosity=0)
    elif lgb is not None:
        model = lgb.LGBMClassifier()
    else:
        from sklearn.ensemble import RandomForestClassifier  # type: ignore[reportMissingImports]
        model = RandomForestClassifier(n_estimators=100, random_state=42)

    model.fit(X, y)
    with open(MODEL_PATH, 'wb') as handle:
        pickle.dump(model, handle)


class ThreatModel:
    def __init__(self):
        train_model_if_needed()
        with open(MODEL_PATH, 'rb') as handle:
            self.model = pickle.load(handle)

    def predict(self, features):
        arr = np.array([features], dtype=float)
        label = self.model.predict(arr)[0]
        prob_func = getattr(self.model, "predict_proba", None)
        if prob_func is not None:
            proba = prob_func(arr)[0]
            score = float(max(proba))
        else:
            score = 1.0
        return {"label": label, "score": score}


model = ThreatModel()
init_db()


def detect_intrusion(samples):
    if not samples:
        return {"status": "no-data", "risk": "low", "attack_type": "none"}

    features = []
    for sample in samples:
        features.append([
            sample.get("bytes", 0) / 10000,
            sample.get("duration", 0),
            1.0 if sample.get("dst_port") in {22, 445, 3389} else 0.0,
            1.0 if sample.get("src_port", 0) > 40000 else 0.0,
        ])

    feature_vector = [sum(row) / len(features) for row in zip(*features)] if features else [0, 0, 0, 0]
    prediction = model.predict(feature_vector)
    score = round(prediction["score"] * 10, 3)
    attack_label = prediction["label"]
    is_attack = attack_label != "Normal"

    if is_attack:
        result = {
            "status": "alert",
            "risk": "high",
            "attack_type": attack_label,
            "explanation": f"The model classified the suspicious traffic as {attack_label} based on the observed pattern.",
            "mitigation": ["Block the source IP", "Enable MFA", "Review authentication logs"],
            "anomaly_score": score,
        }
    else:
        result = {
            "status": "normal",
            "risk": "low",
            "attack_type": "Normal activity",
            "explanation": "The traffic profile looks benign and does not cross the detection threshold.",
            "mitigation": ["Continue monitoring"],
            "anomaly_score": score,
        }

    save_alert(result["risk"], result["attack_type"], result["explanation"])
    return result


def analyze_phishing(email_text):
    lowered = (email_text or "").lower()
    suspicious_markers = ["urgent", "click here", "password", "verify", "invoice", "free money", "prize"]
    score = sum(1 for marker in suspicious_markers if marker in lowered)
    if score >= 2:
        return {"risk": "high", "classification": "phishing", "confidence": min(0.95, 0.55 + score * 0.1)}
    if score == 1:
        return {"risk": "medium", "classification": "suspicious", "confidence": 0.6}
    return {"risk": "low", "classification": "safe", "confidence": 0.4}


def scan_malware(file_name, file_size):
    suspicious_extensions = {".exe", ".dll", ".bat", ".scr", ".vbs"}
    if file_name.lower().endswith(tuple(suspicious_extensions)) or file_size > 5000000:
        return {"risk": "high", "classification": "suspicious", "reason": "Executable or large file pattern matched"}
    return {"risk": "low", "classification": "clean", "reason": "No obvious malware indicators found"}


def explain_threat(result, question):
    q = question.lower()
    if "why" in q or "reason" in q:
        return f"The alert was flagged because the anomaly score reached {result['anomaly_score']} and matched suspicious service-port behavior."
    if "mitigat" in q:
        return "Recommended mitigations: " + "; ".join(result.get("mitigation", []))
    if "attack" in q or "type" in q:
        return f"The detected attack type is {result['attack_type']}."
    return f"The system reports {result['risk']} risk with {result['attack_type']} as the current classification."


def save_alert(risk, attack_type, explanation):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO alerts (risk, attack_type, explanation, created_at) VALUES (?, ?, ?, datetime('now'))", (risk, attack_type, explanation))
    conn.commit()
    conn.close()


def clear_alerts():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()


def capture_live_traffic(interface=None, packet_count=12, timeout=8):
    if sniff is None:
        raise RuntimeError("scapy is not installed")

    packets = sniff(iface=interface, timeout=timeout, count=packet_count)
    metrics_state['last_packet_count'] = len(packets)
    if not packets:
        return []

    start_time = float(packets[0].time)
    samples = []
    for pkt in packets:
        src_port = 0
        dst_port = 0
        if TCP is not None and pkt.haslayer(TCP):
            layer = pkt[TCP]
            src_port = int(layer.sport)
            dst_port = int(layer.dport)
        elif UDP is not None and pkt.haslayer(UDP):
            layer = pkt[UDP]
            src_port = int(layer.sport)
            dst_port = int(layer.dport)

        samples.append({
            "src_port": src_port,
            "dst_port": dst_port,
            "bytes": int(len(pkt)) if hasattr(pkt, '__len__') else 0,
            "duration": round(float(pkt.time) - start_time, 4),
        })
    return samples


def list_alerts():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    rows = cur.execute("SELECT risk, attack_type, explanation, created_at FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return [{"risk": risk, "attack_type": attack_type, "explanation": explanation, "created_at": created_at} for risk, attack_type, explanation, created_at in rows]


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/capture")
def capture():
    interface = request.args.get("interface")
    if sniff is None:
        return jsonify({
            "error": f"scapy is not installed in the running Python interpreter: {sys.executable}. Restart the app using .venv\\Scripts\\python.exe or activate the virtual environment before launching.",
            "samples": [],
        }), 500
    try:
        samples = capture_live_traffic(interface=interface)
    except Exception as exc:
        return jsonify({"error": str(exc), "samples": []}), 500
    return jsonify({"samples": samples})


def get_cpu_usage():
    if psutil is None:
        return 0.0
    return psutil.cpu_percent(interval=0.1)


@app.route("/metrics")
def metrics():
    alerts = list_alerts()
    active_attacks = sum(1 for alert in alerts if alert["risk"] == "high")
    timeline = []
    for alert in alerts[-8:]:
        timeline.append({"time": alert["created_at"], "severity": 80 if alert["risk"] == "high" else 30})
    return jsonify({
        "packet_count": metrics_state.get("last_packet_count", 0),
        "active_attacks": active_attacks,
        "total_alerts": len(alerts),
        "cpu_usage": get_cpu_usage(),
        "attack_timeline": timeline,
    })


@app.route("/status")
def status():
    return jsonify({
        "python": sys.executable,
        "scapy_installed": sniff is not None,
        "scapy_version": None if sniff is None else "installed",
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(force=True)
    samples = payload.get("samples", [])
    return jsonify(detect_intrusion(samples))


@app.route("/ask", methods=["POST"])
def ask():
    payload = request.get_json(force=True)
    question = payload.get("question", "")
    result = detect_intrusion(payload.get("samples", [])) if "samples" in payload else {}
    return jsonify({"answer": explain_threat(result, question) if result else "No data loaded."})


@app.route("/alerts")
def alerts():
    return jsonify(list_alerts())


@app.route("/alerts/clear", methods=["POST"])
def alerts_clear():
    clear_alerts()
    return jsonify({"status": "ok", "message": "Alert history cleared."})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
