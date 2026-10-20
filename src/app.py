from flask import Flask, jsonify, render_template, request  # type: ignore[reportMissingImports]
from database import ThreatDatabase
from ml_model import SimpleThreatModel

app = Flask(__name__, template_folder="templates")

db = ThreatDatabase()
model = SimpleThreatModel()


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

    if prediction["label"] == 1:
        result = {
            "status": "alert",
            "risk": "high",
            "attack_type": "Brute-force / RDP probing",
            "explanation": "The model identified a suspicious access pattern based on elevated port activity and connection characteristics.",
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

    db.save_alert(result["risk"], result["attack_type"], result["explanation"])
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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(force=True)
    samples = payload.get("samples", [])
    result = detect_intrusion(samples)
    return jsonify(result)


@app.route("/ask", methods=["POST"])
def ask():
    payload = request.get_json(force=True)
    question = payload.get("question", "")
    result = detect_intrusion(payload.get("samples", [])) if "samples" in payload else {}
    answer = explain_threat(result, question) if result else "No data loaded."
    return jsonify({"answer": answer})


@app.route("/alerts")
def alerts():
    return jsonify(db.list_alerts())


@app.route("/alerts/clear", methods=["POST"])
def clear_alerts():
    db.clear_alerts()
    return jsonify({"status": "ok", "message": "Alert history cleared."})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
