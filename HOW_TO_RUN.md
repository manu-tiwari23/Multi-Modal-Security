# How to Run MMS (Windows Guide)

Simple, copy-pasteable commands for running Multi Modal Security on Windows.

---

## 1. Quick Demo (No Setup / No Docker Needed)

Runs the complete in-memory attack simulation, SOC rules, correlation, scoring, and test verification in your terminal:

```powershell
.\.venv312\Scripts\Activate.ps1
python demo_pipeline.py
```

> **Execution policy error?** If PowerShell blocks script activation, run this first:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```

---

## 2. Run the Full Platform (Backend API + Dashboard UI)

Open **two PowerShell windows**:

### Terminal 1 — Backend API Gateway:
```powershell
.\.venv312\Scripts\Activate.ps1
uvicorn src.api.main:app --reload --port 8000
```
- **API Health:** [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Interactive Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

### Terminal 2 — React Dashboard:
```powershell
cd src\dashboard
npm install
npm run dev
```
- **Dashboard UI:** Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 3. Trigger Attack Simulations (Real-Time Telemetry)

While the API and Dashboard are running, trigger simulated attacks to see live alerts, score breakdowns, and honeypot events:

### Multi-Stage Attack Scenario:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/simulate/attack" -ContentType "application/json" -Body '{"scenario":"multistage","attacker_ip":"203.0.113.88"}'
```

### SSH Brute Force Only:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/simulate/attack" -ContentType "application/json" -Body '{"scenario":"ssh_brute_force","attacker_ip":"198.51.100.42"}'
```

### Sudo Privilege Escalation:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/simulate/attack" -ContentType "application/json" -Body '{"scenario":"sudo_escalation","attacker_ip":"10.0.0.15"}'
```

### Spearphishing Attack Ingress:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/simulate/attack" -ContentType "application/json" -Body '{"scenario":"phishing","attacker_ip":"203.0.113.88"}'
```

### Scan a Suspicious URL Directly:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/phishing/scan/url" -ContentType "application/json" -Body '{"url":"http://xn--pypal-4ve.com/login/update-password.exe"}'
```

### Scan an Inbound Email:
```powershell
Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/phishing/scan/email" -ContentType "application/json" -Body '{"sender":"security@paypal.com.account-recovery.xyz","subject":"URGENT: Verify account within 24 hours!","body":"Click here to login: http://xn--pypal-4ve.com/auth/login.exe"}'
```

---

## 4. Run Unit Tests (328 Tests)

Make sure your virtual environment is active:

```powershell
# Run all unit tests across the entire project
pytest -v

# Run by module:
pytest tests\phishing\ -v    # Phishing Detection (91 tests)
pytest tests\api\ -v         # API Gateway Endpoints (9 tests)
pytest tests\forensics\ -v   # Digital Forensics (41 tests)
pytest tests\copilot\ -v     # AI Security Copilot (26 tests)
pytest tests\honeypot\ -v    # Honeypot Deception (35 tests)
pytest tests\soc\ -v         # SOC Pipeline (107 tests)
pytest tests\shared\ -v      # Event Schema & Models (11 tests)
```

---

## 5. Docker Containers (Optional)

If you want live Redis Streams, OpenSearch, Postgres, and MinIO:

```powershell
# Start containers
docker compose up -d

# Check status
docker compose ps

# Stop containers
docker compose down
```
*(The platform runs fine without Docker using its built-in in-memory fallbacks).*
