# HPE: Enterprise Network Threat Detection Pipeline

[![ML Pipeline](https://github.com/HPE-Interns/hpe/actions/workflows/ml-pipeline.yml/badge.svg)](https://github.com/HPE-Interns/hpe/actions/workflows/ml-pipeline.yml)
[![CI Pipeline](https://github.com/HPE-Interns/hpe/actions/workflows/ci.yml/badge.svg)](https://github.com/HPE-Interns/hpe/actions/workflows/ci.yml)

HPE is a production-grade, AI-powered cybersecurity threat detection pipeline. It simulates a modern Security Operations Center (SOC) backend and visualizes real-time network traffic interceptions via a stunning 3D WebGL interface, a Structural Spatial (Bento Box) dashboard, and a Security Admin Console with human-in-the-loop credential rotation.

## Overview
The system is designed to ingest raw network traffic, extract behavioral features, execute high-speed machine learning inference in a microservice backend, and trigger automated orchestrated responses (like HashiCorp Vault credential rotation) when a zero-day or malicious pattern is detected.

### Key Feature: Human-in-the-Loop Approval
For BLOCK and CRITICAL severity threats, credential rotation is not automatic. Instead, the system creates a pending alert that an admin must review and approve before Vault rotates credentials. This ensures human oversight over high-impact security actions.

## The Pipeline Architecture
The dashboard visually maps and documents an enterprise-grade 10-stage pipeline. Here is exactly what happens during a real-time event:

* **Network / Apps:** We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.
* **Zeek / Suricata (IDS):** Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).
* **Elastic Beats:** To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.
* **Apache Kafka:** To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as an immutable buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.
* **AI Detection Engine:** The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on a state-of-the-art AI ensemble (XGBoost, LightGBM, Random Forest, Gradient Boosting) to predict if an event is a novel, previously unseen threat.
* **SOAR:** If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human analyst, it automatically triggers conditional incident response playbooks—like isolating machines or initiating automated password resets.
* **HashiCorp Vault (Human-in-the-Loop):** For BLOCK/CRITICAL threats, the system creates a pending admin alert instead of auto-rotating credentials. The admin must review the forensic data, model scores, and pipeline results before approving the rotation.
* **Credential Rotation:** Once approved by an admin, Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services.
* **Credential Distribution:** Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets back to our servers and active microservices using encrypted TLS tunnels, restoring security without taking the system offline.
* **ELK / Grafana:** Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana dashboards.

## Security Admin Console
The admin dashboard provides:

* **Real-time Alert Queue** — Critical and high-severity threats appear as pending alerts
* **Forensic Detail View** — Full event facts, model scores (XGBoost, LightGBM, Ensemble), geo data, and all 10 pipeline stage results
* **Approve / Reject Workflow** — One-click credential rotation approval or false positive rejection
* **Audit Log** — Complete, append-only history of all admin actions with timestamps, admin attribution, and notes
* **WebSocket Notifications** — Instant toast alerts when new critical threats are detected
* **User Registration Management** — Approve or reject pending user access requests from the public login portal
* **Pipeline Reset (Danger Zone)** — Two-step confirmed reset with one-time token (60s TTL); preserves audit log and Kafka topics

### Admin Authentication & Security

The admin console is protected by **JWT-based authentication** with short-lived tokens (30-minute TTL). The JWT signing key is stored in HashiCorp Vault (`hpe/admin-jwt`), ensuring the signing secret is never hardcoded or exposed in environment variables.

* **JWT Auth** — Admins authenticate with Security department credentials; all subsequent API requests carry a `Bearer` token validated via `Depends(get_current_admin)`.
* **Admin Attribution** — Every admin action (approve, reject, reset, registration approval/rejection) is logged with the admin's username for full traceability and non-repudiation.
* **Append-Only Audit Trail** — The `hpe_admin_audit_log` table is never truncated, even during pipeline resets. Reset actions are explicitly recorded in the audit log with the admin's identity and timestamp.
* **Safer Pipeline Reset** — Resets wipe derived state (alerts, metrics, leases) but **preserve** the audit log and Kafka topics (topics are flushed, not deleted, preserving event history and consumer offsets).

## Technologies Used
* **Frontend:** Vanilla JavaScript, Vite, HTML5, CSS3 (Structural Cyber-Bento styling).
* **3D Visualization:** three-globe / globe.gl (WebGL-accelerated geospatial projections).
* **Backend:** Python 3.10+, FastAPI (Asynchronous API and WebSockets).
* **Machine Learning:** scikit-learn, xgboost, lightgbm (Feature Engineering and Ensembling).
* **Infrastructure Layer:** Docker Compose / Kubernetes (Minikube) — Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL.
* **Orchestration:** Minikube with multi-replica HA deployments, StatefulSets, init containers, and PersistentVolumeClaims.

---

## Project Directory Structure

```
hpe/
├── backend/                    # FastAPI Microservice Backend
│   ├── app/
│   │   ├── routes/             # API routes (auth, admin, health, elasticsearch, etc.)
│   │   ├── database.py         # Postgres connection & execute wrapper
│   │   ├── kafka_client.py     # Kafka consumer & producer client
│   │   ├── main.py             # FastAPI App Entrypoint & WebSocket handlers
│   │   ├── threat_engine.py    # AI Threat Scoring & Feature Engineering
│   │   └── vault_client.py     # HashiCorp Vault integrations
│   └── Dockerfile              # Dockerfile for Backend
├── frontend/                   # 3D WebGL cyber-bento dashboard
│   ├── src/
│   │   ├── admin.js            # Admin Console panel & approval/rejection loop
│   │   ├── dashboard.js        # Main Dashboard state & WebSocket streaming
│   │   ├── main.js             # Entrypoint & three-globe/WebGL rendering
│   │   └── styles.css          # Styling & Cyber-Bento Glassmorphic system
│   ├── index.html              # Main HTML entrypoint
│   └── Dockerfile              # Dockerfile for Frontend
├── public-login/               # Nginx-based Public VPN Portal
│   ├── index.html              # Public portal UI login/register
│   ├── styles.css              # Cyberpunk-style login styling
│   └── nginx.conf              # Nginx routing config
├── beats/                      # Log Harvesters & Shippers
│   ├── filebeat.yml            # Core Filebeat config
│   ├── filebeat-live.yml       # Live mode Filebeat parser (dissects Zeek TSV fields)
│   └── filebeat-kafka.yml      # Native Kafka filebeat exporter
├── postgres/
│   └── init/
│       └── 01_schema.sql       # Postgres initialization schema & seed accounts
├── vault/
│   ├── config/
│   │   └── vault.hcl           # HashiCorp Vault cluster configuration
│   └── init/
│       └── setup.sh            # Automated Vault initialization job (AppRole setup, DB engines)
├── scripts/                    # Utility Pipelines & Replay Engines
│   ├── replay_live.py          # Synthetic dataset network live replay writer
│   ├── es_to_kafka.py          # Elasticsearch to Kafka bridge script (watch-optimized)
│   └── generate_zeek_pcap.py   # Synthetic PCAP generation
└── dataset/                    # Network Telemetry Training Logs
    ├── updated_realistic_network_logs.csv  # 100k+ network event records
    ├── updated_realistic_user_profiles.csv  # Behavioral profiles
    └── zeek-live/              # Log harvester target workspace
```

---

## Default Access Ports & Login Credentials

### Ports & URL Mappings

| Service | Local URL / Access | Description |
|---------|---------------------|-------------|
| **3D Security Dashboard** | [http://localhost:5173](http://localhost:5173) | Main Bento-style threat visualizer |
| **Enterprise Login Portal** | [http://localhost:8080](http://localhost:8080) | Public portal vulnerable to brute force / VPN threats |
| **FastAPI Backend API** | [http://localhost:8000](http://localhost:8000) | Microservice threat scoring & WebSocket broker |
| **Adminer Database Manager** | [http://localhost:9090](http://localhost:9090) | GUI database administrator |
| **PostgreSQL Audit DB** | `localhost:5432` | Standard relational log datastore |
| **HashiCorp Vault Server** | [http://localhost:8200](http://localhost:8200) | Secrets storage & dynamic credential provider |
| **Elasticsearch Node** | [http://localhost:9200](http://localhost:9200) | Big data indexer & analyzer |
| **Kibana Log Dashboard** | [http://localhost:5601](http://localhost:5601) | Elasticsearch visualization suite |
| **Apache Kafka Broker** | `localhost:9092` | Stream buffer engine |

### Database Credentials (PostgreSQL)

*   **Database Host:** `hpe-postgres` (Inside Docker network) or `localhost` (Host system)
*   **Database Port:** `5432`
*   **Database Name:** `hpedb`
*   **Superuser/Root Account:**
    *   **Username:** `vault-root`
    *   **Password:** `vault-root-secret`
*   **Vault Managed Service Account:** Dynamic roles generated by Vault under `database/creds/hpe-app`. These are rotated automatically on threat approvals.

### Seed User Accounts (Enterprise Portal)

You can log in to the **Enterprise Portal** (`http://localhost:8080/`) using the following default pre-configured credentials:

| Username | Password | Department / Role | Status |
|----------|----------|-------------------|--------|
| `admin` | `admin123` | Security (Admin) | Active |
| `alice` | `password123` | Engineering | Active |
| `bob` | `password123` | HR | Active |
| `charlie` | `password123` | Finance | Active |

---

## Project Setup

You can run this project in **three ways**:

| Mode | Best For | Infrastructure |
|------|----------|---------------|
| **Option 1** — Docker Compose | Full stack on a single machine | Docker Desktop |
| **Option 2** — Kubernetes (Minikube) | Production-grade HA deployment | Minikube + kubectl |
| **Option 3** — Local Demo (No Docker) | UI development / low-resource machines | Python + Node.js only |

---

### Prerequisites (All Options)

**Generate ML model artifacts** (required once, or after dataset changes):
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```
This creates `model_output/pipeline_artifacts_v2.joblib`, `test_events.json`, and `user_profiles.json`.

---

### Option 1: Full Enterprise Stack (Docker Compose) 🐳
*Recommended for single-machine testing.*

This method automatically builds, mounts, and orchestrates the entire containerized architecture: Kafka, Elasticsearch, Kibana, HashiCorp Vault, PostgreSQL, the FastAPI AI Backend, the Vite 3D Frontend, Nginx (serving the Public Login Portal), Adminer, and a pre-configured Ngrok Tunnel.

**Prerequisites:**
* Docker Desktop running with at least **8 GB of Memory** allocated (required for Elasticsearch)
* Python 3.10+ installed locally

#### 🚀 Recommended Fast Startup (One-Click)

We have provided a **one-shot launcher** that automates the whole deployment, checks prerequisites, builds files, and extracts details.

On **Windows PowerShell / Command Prompt**, simply run:
```bash
run-compose
```

**What the launcher script does for you:**
1. **Verifies Prerequisites:** Confirms Docker is active.
2. **Generates ML Models:** Detects if machine learning pipeline artifacts are present. If missing, it installs the necessary packages and generates them automatically.
3. **One-Command Orchestration:** Starts the default stack AND the `live-replay` profile (`docker compose --profile live-replay up -d --build`).
4. **Health Checker:** Loops until the Backend, Vault, and Postgres report as healthy.
5. **Dynamic Ngrok Tunnel Extraction:** Retrieves the dynamic public URL of the Public Login Portal from the active Ngrok status endpoint and prints it out automatically.

---

#### 🛠️ Manual Startup (Alternative)

If you prefer starting components manually:

**Step 1 — Start the full stack:**
```bash
# Start core services and the live-replay pipeline
docker compose --profile live-replay up -d --build
```
On **first boot**, allow **2-3 minutes** for all services to fully initialize.

**Step 2 — Open the application:**
Once all systems are healthy, open your browser and navigate to:
* **3D Security Dashboard:** http://localhost:5173
* **Public Login Portal:** http://localhost:8080
* **Adminer Database Manager:** http://localhost:9090

> **Note on restarts:** If you stop with `docker compose down` (without `-v`), Vault will start in a sealed state on the next startup. You can automatically unseal Vault and re-authenticate the backend with a single command:
> ```bash
> # Restart Vault and Vault-Init to trigger automated unsealing
> docker compose restart vault vault-init
> 
> # Restart the backend and proxy to establish a fresh AppRole session
> docker compose restart backend login-portal
> ```


---

### Option 2: Kubernetes on Minikube ☸️
*Recommended for production-grade, high-availability deployment.*

This deploys the entire pipeline into a Kubernetes cluster with **HA replicas** (2 Kafka brokers, 2 backend pods, 2 frontend pods), StatefulSets for stateful services, and a Vault init Job for automated secrets management.

#### Architecture Highlights

| Component | K8s Resource | Replicas | Notes |
|-----------|-------------|----------|-------|
| Kafka | StatefulSet | 2 | KRaft mode, headless service with `publishNotReadyAddresses` |
| Elasticsearch | StatefulSet | 1 | Single-node dev mode, 1 Gi PVC |
| PostgreSQL | StatefulSet | 1 | Init ConfigMap for schema + extensions |
| Vault | StatefulSet | 1 | Raft storage on PVC, server mode with auto-unseal sidecar |
| Vault Init | Job | 1 (run-once) | Phases 1-5: init, unseal, DB engine, AppRole, Kafka creds |
| Backend | Deployment | 5 | Init container waits for all deps + `.approle_credentials` |
| Frontend | Deployment | 3 | Vite dev server behind NodePort |

#### Prerequisites
* **Minikube** installed and running (`minikube start --memory=8192 --cpus=4`)
* **kubectl** configured to point at your Minikube cluster
* **Docker CLI** available (for building images into Minikube's Docker daemon)
* Python 3.10+ (for the model export step)

#### Step 1 — Start Minikube
```bash
minikube start --memory=8192 --cpus=4
```

#### Step 2 — Generate ML artifacts (if not done)
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

#### Step 3 — Deploy with the automated script (Windows PowerShell)
The project includes a **one-shot deployment script** that handles everything:
```powershell
# Full deployment (builds images + deploys all manifests)
.\deploy.ps1

# Skip image rebuilds (faster, if images are already built)
.\deploy.ps1 -SkipBuild

# Clean slate: delete namespace first, then redeploy
.\deploy.ps1 -DeleteFirst

# Fresh: deploy + wipe all pipeline data after startup
.\deploy.ps1 -Fresh
```

The script performs these 7 phases:
1. **Configure Docker** — Points Docker CLI at Minikube's daemon
2. **Build images** — `hpe-backend:latest` and `hpe-frontend:latest` inside Minikube
3. **Create namespace + config** — Applies namespace, ConfigMap, Secrets, PVC
4. **Deploy infrastructure** — PostgreSQL, Kafka (2 brokers), Elasticsearch, Vault RBAC, Vault
5. **Vault initialization** — Runs the vault-init Job (init → unseal → database engine → AppRole → credential file)
6. **Deploy application** — Backend (5 replicas) + Frontend (3 replicas)
7. **Enable HPA** — Horizontal Pod Autoscaler for backend

#### Step 4 — Manual deployment (Linux/Mac or if not using PowerShell)

If you are **not** on Windows PowerShell, run the equivalent commands manually:

```bash
# Point Docker to Minikube
eval $(minikube docker-env)

# Build images inside Minikube
docker build -t hpe-backend:latest -f backend/Dockerfile .
docker build -t hpe-frontend:latest -f frontend/Dockerfile ./frontend

# Create namespace and config
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/vault-pvc.yaml

# Deploy infrastructure
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/kafka/
kubectl apply -f k8s/elasticsearch/

# Apply Vault RBAC before the StatefulSet so the ServiceAccount exists when the pod schedules
kubectl apply -f k8s/vault/vault-rbac.yaml
kubectl apply -f k8s/vault/vault-config-configmap.yaml
kubectl apply -f k8s/vault/vault-service.yaml
kubectl apply -f k8s/vault/vault-statefulset.yaml

# Wait for infrastructure pods
kubectl wait --for=condition=Ready pod -l app=kafka -n hpe --timeout=240s
kubectl wait --for=condition=Ready pod -l app=elasticsearch -n hpe --timeout=180s
kubectl wait --for=condition=Ready pod -l app=vault -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=postgres -n hpe --timeout=120s

# Run Vault init Job
kubectl apply -f k8s/vault/vault-init-configmap.yaml
kubectl apply -f k8s/vault/vault-init-job.yaml
kubectl wait --for=condition=Complete job/vault-init -n hpe --timeout=180s

# Deploy application
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/

# Wait for app pods
kubectl wait --for=condition=Ready pod -l app=backend -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=frontend -n hpe --timeout=120s
```

#### Step 5 — Access the dashboard
```bash
minikube service frontend -n hpe
```
This opens a browser tunnel to the frontend NodePort service.

#### Useful Kubernetes Commands
```bash
# Check pod status
kubectl get pods -n hpe

# View logs for a specific pod
kubectl logs -f deployment/backend -n hpe

# View Vault init logs
kubectl logs job/vault-init -n hpe

# View auto-unseal sidecar logs
kubectl logs vault-0 -c unseal-watcher -n hpe

# Port-forward backend for direct API access
kubectl port-forward service/backend 8000:8000 -n hpe

# Tear down everything
kubectl delete namespace hpe
```

#### Vault Unsealing After Restart

> **Why does Vault seal itself?**
> Vault uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) as a security mechanism. Every time Vault's container restarts (e.g., after `minikube stop` → `minikube start`), Vault deliberately seals itself. This is **by design** — if someone gains physical access to the server, they cannot read any secrets without the unseal key.

Unsealing is handled automatically. The Vault pod runs an `unseal-watcher` sidecar container that polls Vault's seal status every 15 seconds and calls the unseal API whenever it detects Vault has sealed itself after a restart — no manual steps required.

If the dashboard shows **Vault** as red (🔴) after a Minikube restart, the sidecar will restore it automatically within 15 seconds. You can watch it in real time:

```bash
kubectl logs vault-0 -c unseal-watcher -n hpe -f
```

Once Vault is unsealed, restart the backend so it reconnects:
```bash
kubectl rollout restart deployment/backend -n hpe
```

After this, refresh the dashboard — the Vault indicator should turn green (🟢).

---

### Option 3: Local Demo Mode (No Docker) 💻
*Recommended for UI development or low-resource machines.*

If you do not want to spin up the heavy infrastructure containers, you can run the backend and frontend scripts directly on your local system. The dashboard will intelligently fall back to generating simulation traffic locally.

#### 🚀 Recommended Fast Startup (One-Click)

We have provided a **one-shot local launcher** that automates the entire local setup process.

On **Windows PowerShell / Command Prompt**, simply run:
```bash
run-local
```

**What the launcher script does for you:**
1. **Verifies Prerequisites:** Confirms Python 3.10+ and Node.js (v18+) are installed.
2. **Generates ML Models:** Checks if machine learning pipeline artifacts are present. If missing, it installs the necessary packages and generates them automatically.
3. **Creates Python Venv:** Creates a virtual environment in `backend/venv` and runs `pip install` for backend dependencies.
4. **Installs Node Modules:** Installs required packages in the `frontend` folder if missing.
5. **Starts Application Services:** Boots the FastAPI backend on port `8000` and the Vite frontend on port `5173` in separate popped-up console windows.
6. **Autoplays Browser:** Automatically opens `http://localhost:5173` in your default web browser.

---

#### 🛠️ Manual Startup (Alternative)

If you prefer starting components manually:

**Step 1: Generate model artifacts (if not already done):**
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

**Step 2: Start the Backend (API & Simulation)**
```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000
```
*Because Kafka and Elastic are not active, the backend API will safely fallback into test mode.*

**Step 3: Start the Frontend (3D UI)**
Open a **new** terminal window and run:
```bash
cd frontend

# Install Node modules
npm install

# Start the Vite development server
npm run dev
```
Navigate to **http://localhost:5173**. The application will automatically use "Local Simulation" mode.

---

### Admin API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/admin/login` | None | Exchange Security department credentials for a JWT |
| GET | `/api/admin/alerts` | JWT | List all alerts (filter: `?status=pending&severity=critical`) |
| GET | `/api/admin/alerts/{id}` | JWT | Full forensic detail for an alert |
| POST | `/api/admin/alerts/{id}/approve` | JWT | Approve credential rotation (logs admin attribution) |
| POST | `/api/admin/alerts/{id}/reject` | JWT | Reject as false positive (logs admin attribution) |
| GET | `/api/admin/stats` | JWT | Dashboard summary statistics |
| GET | `/api/admin/audit-log` | JWT | History of admin actions |
| GET | `/api/admin/infra-leases` | JWT | Active Vault infrastructure leases and Kafka credential status |
| GET | `/api/admin/registrations` | JWT | List pending user access requests |
| POST | `/api/admin/registrations/{user}/approve` | JWT | Approve a pending user and set credentials |
| POST | `/api/admin/registrations/{user}/reject` | JWT | Reject and delete a pending registration |
| POST | `/api/admin/reset/request` | JWT | Generate a one-time pipeline reset token (60s TTL) |
| POST | `/api/admin/reset/confirm` | JWT | Execute pipeline reset with a valid confirmation token |
| WS | `/api/admin/ws` | JWT (query param) | Real-time alert notifications |

---

### Kubernetes Manifest Structure
```
k8s/
├── namespace.yaml              # hpe namespace
├── configmap.yaml              # Shared env vars (Kafka, ES, Vault URLs)
├── secrets.yaml                # VAULT_TOKEN fallback secret
├── vault-pvc.yaml              # Shared PVC for Vault data + AppRole creds
├── kafka/
│   ├── kafka-headless-service.yaml   # Headless service (publishNotReadyAddresses)
│   └── kafka-statefulset.yaml        # 2-broker KRaft cluster
├── elasticsearch/
│   ├── es-service.yaml
│   └── es-statefulset.yaml
├── postgres/
│   ├── postgres-init-configmap.yaml  # Schema, pgcrypto, tables
│   ├── postgres-service.yaml
│   └── postgres-statefulset.yaml
├── live-pipeline/
│   ├── es-to-kafka-deployment.yaml
│   ├── live-pipeline-configmap.yaml
│   └── live-replay-deployment.yaml
├── redis/
│   ├── redis-deployment.yaml
│   └── redis-service.yaml
├── vault/
│   ├── vault-rbac.yaml               # ServiceAccount, Role, RoleBinding for Vault pod
│   ├── vault-config-configmap.yaml   # vault.hcl server config
│   ├── vault-init-configmap.yaml     # Full init script (Phases 1-5)
│   ├── vault-init-job.yaml           # One-shot init Job
│   ├── vault-service.yaml
│   └── vault-statefulset.yaml        # Includes auto-unseal sidecar
├── backend/
│   ├── backend-deployment.yaml       # 5 replicas + init container
│   ├── backend-hpa.yaml              # Horizontal Pod Autoscaler
│   └── backend-service.yaml
└── frontend/
    ├── frontend-deployment.yaml      # 3 replicas
    └── frontend-service.yaml
```

---

### Dataset

The training dataset is included in `dataset/`:
- `updated_realistic_network_logs.csv` — 100K+ network events with injected anomalies
- `updated_realistic_user_profiles.csv` — User behavioral profiles

---

#### Pipeline Mode 1: One-Shot (Dataset → Zeek → Beats → ES → Kafka)

Process the entire dataset through the pipeline in a single pass:

1. Generate a synthetic PCAP from the CSV (or capture live network traffic):
   ```bash
   # Synthetic mode (default)
   python scripts/generate_zeek_pcap.py
   
   # Live capture mode (requires scapy: pip install scapy)
   python scripts/generate_zeek_pcap.py --live --duration 60 --interface eth0
   ```
2. Start Zeek and Filebeat via Docker Compose:
   ```bash
   docker compose up -d zeek filebeat elasticsearch kafka
   ```
3. Filebeat reads `dataset/zeek/conn.log` and ships events into Elasticsearch.
4. Run the Elasticsearch → Kafka bridge service:
   ```bash
   docker compose up -d es-to-kafka
   ```
   This executes `scripts/es_to_kafka.py` (now with `--watch` mode) and continuously publishes documents from `zeek-conn-*` into Kafka topic `hpe-raw-events`.

---

#### Pipeline Mode 2: Live Replay (Dataset streamed as live traffic)

Replay the dataset as if it were live network traffic — events arrive one at a time at a controlled rate through the full pipeline:

```
scripts/replay_live.py ──writes──▶ dataset/zeek-live/conn.log
                                   │
                              Filebeat (tail mode)
                                   │
                              Elasticsearch
                                   │
                              scripts/es_to_kafka.py (--watch)
                                   │
                                 Kafka  ──▶  AI Backend
```

**Option A — Via Docker Compose (recommended):**
```bash
# Start the core infrastructure + live replay pipeline
docker compose up -d elasticsearch kafka
docker compose --profile live-replay up -d

# Also start the ES→Kafka bridge
docker compose up -d es-to-kafka

# Adjust replay speed via environment variable (default: 50 events/sec)
REPLAY_RATE=100 docker compose --profile live-replay up -d
```

**Option B — Direct to Kafka (skip ES bridge, lowest latency):**
```bash
docker compose up -d kafka
docker compose --profile live-kafka up -d

# scripts/replay_live.py must also be running to feed events
python scripts/replay_live.py --rate 50 --loop
```

**Option C — Run replay locally (no Docker for replay):**
```bash
# Start infrastructure in Docker
docker compose up -d elasticsearch kafka

# Run replay on your local machine
python scripts/replay_live.py --rate 50 --loop

# Start filebeat-live in Docker (it reads dataset/zeek-live/)
docker compose --profile live-replay up -d filebeat-live
docker compose up -d es-to-kafka
```

**Replay script options:**
```bash
python scripts/replay_live.py --help

# Default: 50 events/sec, one pass
python scripts/replay_live.py

# Custom rate, infinite loop
python scripts/replay_live.py --rate 100 --loop

# Burst mode (max speed), 3 passes
python scripts/replay_live.py --rate 0 --repeat 3

# Clean previous output first
python scripts/replay_live.py --clean --loop
```

To retrain the model, run:
```bash
python export_v2_model.py
```

---

### Teardown 🛑

**Docker Compose:**
```bash
# Graceful stop
docker-compose down

# Hard reset (wipes all databases, Kafka topics, Vault secrets)
docker-compose down -v
```

**Kubernetes (Minikube):**
```bash
# Delete everything in the hpe namespace
kubectl delete namespace hpe

# Optionally stop Minikube
minikube stop
```

After a hard reset, re-run `python export_v2_model.py` before starting again.

---

### Model Performance Gate

The ML pipeline enforces a minimum **Threat class F1 score of 0.70** before a trained model can be uploaded as a CI artifact. The gate runs automatically on every push that touches `export_v2_model.py`, the dataset, or the inference code. If the score falls below the threshold, the workflow exits non-zero and blocks the artifact upload.

The threshold is controlled by `MIN_F1_THRESHOLD` in `.github/workflows/ml-pipeline.yml`. After each successful run, a formatted results table (F1, precision, recall, best threshold, training duration) is written to the GitHub Actions job summary and visible directly in the PR UI.

## Team
HPE Code Project Interns
