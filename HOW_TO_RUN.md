# How to Run MMS on Windows

These commands match the current persistent backend and authenticated dashboard.

> Run every command from the repository root unless a section explicitly changes directory:
>
> ```powershell
> Set-Location "C:\Users\manut\OneDrive - Gamers Flight\Desktop\Multi Modal Security"
> ```

---

## 1. One-time local setup

### Check the required programs

```powershell
docker version
node --version
npm --version
py -3.12 --version
```

If `docker version` cannot connect to the engine, open Docker Desktop and wait until it reports that the engine is running.

### Create the Python environment if it is missing

```powershell
if (-not (Test-Path ".\.venv312\Scripts\python.exe")) {
    py -3.12 -m venv .venv312
}

& ".\.venv312\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv312\Scripts\python.exe" -m pip install -r requirements.txt
```

These commands use the virtual environment's Python directly. PowerShell script activation is not required.

### Create the local environment file if it is missing

```powershell
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}
```

The development values in `.env.example` match `docker-compose.yml`. Do not commit `.env` or place real API keys in documentation.

---

## 2. Start the required infrastructure

The full platform currently uses persistent storage by default, so Docker is required. Start the five services used by the API:

```powershell
docker compose up -d redis opensearch postgres minio mosquitto
docker compose ps
```

Wait until Redis, OpenSearch, PostgreSQL, and MinIO show `healthy`. The following command waits for them:

```powershell
$containers = @("mms-redis", "mms-opensearch", "mms-postgres", "mms-minio")
$deadline = (Get-Date).AddMinutes(3)

do {
    $states = foreach ($container in $containers) {
        docker inspect --format '{{.State.Health.Status}}' $container 2>$null
    }
    Write-Host "Service health: $($states -join ', ')"
    if ($states.Count -eq 4 -and @($states | Where-Object { $_ -ne "healthy" }).Count -eq 0) {
        break
    }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)

if (@($states | Where-Object { $_ -ne "healthy" }).Count -ne 0) {
    throw "Infrastructure did not become healthy. Run: docker compose logs --tail 100"
}
```

Do not start the backend before these services are healthy. If the backend was already running while Docker was stopped, stop it with `Ctrl+C` and restart it after the health check passes.

---

## 3. Create the first dashboard account

Run this once after PostgreSQL is healthy:

```powershell
& ".\.venv312\Scripts\python.exe" -m src.auth.cli create admin --role admin
```

Enter a password of 15–128 characters when prompted. The password is hidden and is not written to the command history.

If the `admin` account already exists, do not recreate it. To set a new password instead, run:

```powershell
& ".\.venv312\Scripts\python.exe" -m src.auth.cli reset-password admin
```

---

## 4. Start the backend API

Open a new PowerShell window, return to the repository root, and run:

```powershell
Set-Location "C:\Users\manut\OneDrive - Gamers Flight\Desktop\Multi Modal Security"
& ".\.venv312\Scripts\python.exe" -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Keep this window open. A successful startup ends with:

```text
Application startup complete.
Uvicorn running on http://127.0.0.1:8000
```

In another PowerShell window, verify the API:

```powershell
$health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -TimeoutSec 10
$health | Format-List
```

The result should include `status : ok`. You can also open:

- API health: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)
- API documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### If port 8000 is already in use

Inspect the process first:

```powershell
$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    Get-Process -Id $listener.OwningProcess | Select-Object Id, ProcessName, Path
}
```

Return to the terminal running that backend and press `Ctrl+C`. Only if it is a confirmed stale MMS Python process, stop it with:

```powershell
Stop-Process -Id $listener.OwningProcess
```

Then run the backend command again.

---

## 5. Start the React dashboard

Open another PowerShell window:

```powershell
Set-Location "C:\Users\manut\OneDrive - Gamers Flight\Desktop\Multi Modal Security\src\dashboard"
npm install
npm run dev -- --host 127.0.0.1
```

Keep this window open and visit:

- Dashboard: [http://127.0.0.1:5173](http://127.0.0.1:5173)

Sign in with the account created in section 3. The dashboard development server forwards `/api` and WebSocket requests to `http://localhost:8000`.

---

## 6. Demonstrate the platform

The recommended presentation flow is authenticated and available inside the dashboard:

1. Sign in as an analyst or administrator.
2. Open **Simulation Lab**.
3. Run **Full platform showcase** with the reserved IP `203.0.113.88`.
4. Review the resulting Incidents, Telemetry, Honeypot, Phishing, Response, Reports, and Copilot views.
5. Use the Simulation Lab's demo-data kit for safe IP, domain, URL, hash, email, attachment, and forensic-file samples.

### Optional authenticated PowerShell simulation

Protected API actions require a login cookie and CSRF token. This example prompts for the password without storing it in the script:

```powershell
$username = "admin"
$securePassword = Read-Host "MMS password" -AsSecureString
$password = [System.Net.NetworkCredential]::new("", $securePassword).Password
$webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$origin = "http://127.0.0.1:5173"

$login = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/auth/login" `
    -WebSession $webSession `
    -Headers @{ Origin = $origin } `
    -ContentType "application/json" `
    -Body (@{ username = $username; password = $password } | ConvertTo-Json)

$headers = @{
    Origin = $origin
    "X-MMS-CSRF" = $login.csrf_token
}

Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8000/api/simulate/attack" `
    -WebSession $webSession `
    -Headers $headers `
    -ContentType "application/json" `
    -Body '{"scenario":"multistage","attacker_ip":"203.0.113.88"}'

$password = $null
```

Unauthenticated `Invoke-RestMethod` calls to protected simulation or analysis endpoints are expected to fail with HTTP 401 or 403.

---

## 7. Run tests

From the repository root:

```powershell
& ".\.venv312\Scripts\python.exe" -m pytest -q --tb=short -ra
```

Run an individual module with the same Python environment:

```powershell
& ".\.venv312\Scripts\python.exe" -m pytest tests\phishing -v
& ".\.venv312\Scripts\python.exe" -m pytest tests\api -v
& ".\.venv312\Scripts\python.exe" -m pytest tests\forensics -v
& ".\.venv312\Scripts\python.exe" -m pytest tests\copilot -v
& ".\.venv312\Scripts\python.exe" -m pytest tests\honeypot -v
& ".\.venv312\Scripts\python.exe" -m pytest tests\soc -v
```

---

## 8. Troubleshooting

### Backend window closes immediately or `No module named src` appears

You are not in the repository root. Run the exact `Set-Location` command from section 4, then retry.

### `No module named uvicorn` or `No module named pytest`

Use `& ".\.venv312\Scripts\python.exe" -m ...`, not a system-wide `python`, `uvicorn`, or `pytest` command. If the error remains, repeat the dependency-install commands from section 1.

### Health endpoint returns HTTP 503

Check infrastructure:

```powershell
docker compose ps
docker compose logs --tail 100 postgres redis opensearch minio
```

Start any missing services, wait for `healthy`, then restart the backend. Persistent mode intentionally does not silently fall back to temporary in-memory storage.

### Dashboard says the sign-in service is unavailable

Confirm that the backend health endpoint returns `status : ok`. If it does not, fix the backend first. If health is good, confirm the dashboard is running on `127.0.0.1:5173` and that `.env` contains that origin in `AUTH_ALLOWED_ORIGINS`.

### Dashboard loads but telemetry is unavailable

Make sure both terminal windows remain open. Confirm the API is still listening on port 8000 and refresh the dashboard after `/api/health` returns successfully.

### Inspect recent service logs

```powershell
docker compose logs --tail 100
```

---

## 9. Stop the platform

1. Press `Ctrl+C` in the backend terminal.
2. Press `Ctrl+C` in the dashboard terminal.
3. Stop the infrastructure containers without deleting their data:

```powershell
Set-Location "C:\Users\manut\OneDrive - Gamers Flight\Desktop\Multi Modal Security"
docker compose stop
```

To start again later, repeat sections 2, 4, and 5. Do not use `docker compose down -v` unless you intentionally want to delete all stored development data and accounts.

---

## Quick startup after one-time setup

From the repository root:

```powershell
docker compose up -d redis opensearch postgres minio mosquitto
docker compose ps
& ".\.venv312\Scripts\python.exe" -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Then, in a second PowerShell window:

```powershell
Set-Location "C:\Users\manut\OneDrive - Gamers Flight\Desktop\Multi Modal Security\src\dashboard"
npm run dev -- --host 127.0.0.1
```
