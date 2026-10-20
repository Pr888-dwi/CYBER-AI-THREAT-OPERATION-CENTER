# CyberAI: AI-Powered Cybersecurity Platform

CyberAI is an end-to-end cybersecurity platform that combines intrusion detection, phishing analysis, malware scanning, threat intelligence, and an LLM-powered SOC assistant into one portfolio-ready solution.

## Core Modules
- AI Intrusion Detection
- AI Phishing Detection
- AI Malware Scanner
- Threat Intelligence Dashboard
- LLM-powered SOC Assistant
- Incident Report Generator
- Email and Telegram alerting
- Docker deployment
- Cloud hosting support for AWS/Azure

## Architecture Overview
1. Data Ingestion
   - Network logs, email samples, malware artifacts, and threat feeds
2. AI Detection Layer
   - ML models for anomaly and phishing detection
   - Heuristic and signature-based checks for malware
3. Threat Intelligence Layer
   - Correlation engine and risk scoring
4. LLM Assistant Layer
   - Natural language explanation and mitigation suggestions
5. Notification Layer
   - Email and Telegram alerts
6. Deployment Layer
   - Dockerized services for easy cloud deployment

## Suggested Tech Stack
- Python
- Flask/FastAPI
- scikit-learn
- pandas
- joblib
- OpenAI / Azure OpenAI API
- Celery + Redis
- PostgreSQL / SQLite
- Docker
- AWS EC2 / Azure Container Apps
- AI attack classification into categories such as DDoS, SQL Injection, Port Scan, Brute Force, Malware, Botnet, Ransomware, and Data Exfiltration
- Real-time dashboard with live charts and system metrics

## Project Roadmap
- Phase 1: Prototype dashboard with mock detections
- Phase 2: Add ML-based intrusion and phishing models
- Phase 3: Add malware scanning engine and report generation
- Phase 4: Add alerting and deployment automation
- Phase 5: Publish GitHub repository and research paper

## Run the App Locally
1. Activate the virtual environment:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```
3. Start the Flask app:
   ```powershell
   python single_app.py
   ```
4. Open the app in your browser:
   ```
   http://127.0.0.1:5000
   ```

> Live packet capture is supported via the `Capture Live Traffic` button in the UI. Install `scapy` in the activated virtual environment and run the app with administrative privileges so the backend can sniff packets.
>
> The UI also includes a real-time dashboard with:
> - Packet count
> - Active attacks
> - CPU usage
> - Threat severity timeline
>
> The model now performs AI attack classification into categories like DDoS, SQL Injection, Port Scan, Brute Force, Malware, Botnet, Ransomware, and Data Exfiltration.
>
> If you need network access from another device, the app also listens on `0.0.0.0:5000`.

## Deploy on Render
1. Push this project to a GitHub repository. Make sure `render.yaml`, `.python-version`, and `requirements.txt` are at the repository root.
2. In Render, choose **New +** -> **Blueprint**, connect the GitHub repository, and select the branch to deploy. Render will read `render.yaml` and build the `cyberai` web service.
3. When the first deploy finishes, open the service URL shown in the Render dashboard.

The Render service runs `single_app.py` through Gunicorn and binds to Render's assigned port. No environment variables are required for the current app. The free service's local filesystem is ephemeral, so alert history and generated model files can be lost when the service restarts or redeploys. Live packet capture is not available on Render; use the sample traffic input or deploy to a host where packet capture is supported.

## Portfolio Value
This project is strong for product-based companies because it demonstrates:
- end-to-end system design
- AI + cybersecurity integration
- real-world workflow thinking
- deployment and scalability awareness
