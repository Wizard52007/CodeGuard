# CodeGuard
Real-time, CPU-based security analysis and execution interception for AI-generated code

CodeGuard statically analyzes submitted code. Submitted code is never executed by the analysis endpoint.

## Run locally (Windows PowerShell)

Requires Python 3.12+ and Node.js 20.19+ (or 22.12+).

**Backend** (from the repository root):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

**Frontend** (second terminal, from `frontend/`):

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/health`, `/evaluate` and `/demo/intercept` to `http://127.0.0.1:8000`, so no CORS setup is needed. Set `CODEGUARD_API_TARGET` to point the proxy elsewhere.

**Tests**

```powershell
python -m pytest -q          # backend, from the repository root
cd frontend; npm test        # frontend
npm run build                # frontend production build
```

## Deploying the frontend separately

Set the backend URL at build time (Vite exposes only `VITE_*` variables to the browser):

```powershell
$env:VITE_API_BASE_URL = "https://your-backend.example.com"
npm run build
```

Do not put secrets in frontend variables. A cross-origin backend must allow the frontend origin through CORS; the backend does not configure CORS today.
