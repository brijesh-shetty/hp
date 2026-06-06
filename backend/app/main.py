"""
main.py — FastAPI application entry point for the HPE Threat Detection Pipeline.
Handles startup/shutdown lifecycle, CORS, and route registration.

Changes from original:
- Added Redis pub/sub listener startup for cross-pod WebSocket broadcasting.
  Without this, events consumed by pod-A never reach browsers connected to pod-B.
  Redis acts as a shared message bus so ALL pods broadcast to ALL browsers.
- Falls back gracefully if Redis is not available (single-pod / local mode).
"""

import logging
import asyncio
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import APP_NAME, APP_TAGLINE, APP_VERSION, MODEL_PATH
from app import inference, kafka_client, elastic_client, vault_client, vault_infra_client
from app.routes import predict, health, pipeline, simulate, admin
from app.ws_manager import manager as ws_manager, admin_manager
from app.threat_engine import process_raw_event
from app import admin_store

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hpe.main")


# ── Lifespan (startup/shutdown) ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle — load models and connect to infrastructure."""
    logger.info(f"{'='*60}")
    logger.info(f"  {APP_NAME} — {APP_TAGLINE}")
    logger.info(f"  Version: {APP_VERSION}")
    logger.info(f"{'='*60}")

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    try:
        from app import db
        db.init_pool()
        logger.info("[OK] PostgreSQL pool initialized")
        try:
            users = db.execute_query("SELECT id, username, department, status, password_hash FROM hpe_users", fetch=True, fetch_all=True)
            logger.info(f"[DB INSPECTION] Found {len(users)} users in hpe_users:")
            for u in users:
                pw_status = "present" if u.get('password_hash') else "NULL"
                logger.info(f"  - User: {u.get('username')}, Dept: {u.get('department')}, Status: {u.get('status')}, Password: {pw_status}")
        except Exception as inspect_err:
            logger.error(f"[DB INSPECTION FAIL] Could not query hpe_users: {inspect_err}")
    except Exception as e:
        logger.error(f"[FAIL] PostgreSQL pool init failed: {e}")

    # ── Load persisted metrics from Postgres ───────────────────────────────────
    try:
        from app import threat_engine
        threat_engine.load_metrics_from_db()
    except Exception as e:
        logger.error(f"[FAIL] Loading metrics from DB failed: {e}")

    # ── Load persisted admin state ─────────────────────────────────────────────
    try:
        from app import admin_store
        admin_store.load_from_db()
    except Exception as e:
        logger.error(f"[FAIL] Loading admin store from DB failed: {e}")

    # ── ML model ───────────────────────────────────────────────────────────────
    try:
        inference.load_model(MODEL_PATH)
        logger.info("[OK] ML model loaded successfully")
    except Exception as e:
        logger.error(f"[FAIL] ML model loading failed: {e}")

    # ── Kafka ──────────────────────────────────────────────────────────────────
    try:
        kafka_connected = kafka_client.connect_kafka()
        if kafka_connected:
            logger.info("[OK] Kafka connected")
        else:
            logger.warning("[WARN] Kafka connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Kafka unavailable: {e}")

    # ── Elasticsearch ──────────────────────────────────────────────────────────
    try:
        es_connected = elastic_client.connect_elasticsearch()
        if es_connected:
            logger.info("[OK] Elasticsearch connected")
        else:
            logger.warning("[WARN] Elasticsearch connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Elasticsearch unavailable: {e}")

    # ── Vault (user-level KV) ──────────────────────────────────────────────────
    try:
        vault_connected = vault_client.connect_vault()
        if vault_connected:
            logger.info("[OK] HashiCorp Vault connected")
        else:
            logger.warning("[WARN] Vault connection failed — running in fallback mode")
    except Exception as e:
        logger.warning(f"[WARN] Vault unavailable: {e}")

    # ── Load admin JWT signing secret from Vault ──────────────────────────────
    try:
        from app import auth_admin
        auth_admin.load_jwt_secret()
    except Exception as e:
        logger.warning(f"[WARN] Admin JWT secret not loaded: {e} — admin auth will use fallback")

    # ── Vault infra client (database secrets engine) ───────────────────────────
    try:
        if vault_client.is_connected() and vault_client._client is not None:
            infra_connected = vault_infra_client.connect(vault_client._client)
            if infra_connected:
                logger.info("[OK] Vault infrastructure client connected (database secrets engine)")
            else:
                logger.warning("[WARN] Vault infra client failed — infrastructure rotation unavailable")
        else:
            logger.warning("[WARN] Vault not connected — skipping infra client setup")
    except Exception as e:
        logger.warning(f"[WARN] Vault infra client unavailable: {e}")

    # ── Redis pub/sub listeners ────────────────────────────────────────────────
    # This is the key fix for multi-replica deployments.
    #
    # Problem without Redis:
    #   Pod-A consumes Kafka partition 1 → detects threat → broadcasts to Pod-A's ws_manager
    #   Browser is connected to Pod-B's ws_manager → never receives the event
    #
    # Fix with Redis:
    #   Pod-A detects threat → publishes to Redis channel
    #   ALL pods (A, B, C...) are subscribed to Redis → all broadcast to their browsers
    #   Every browser receives every event regardless of which pod it connected to
    #
    # Falls back gracefully to local-only mode if Redis is not available.
    try:
        loop = asyncio.get_running_loop()
        ws_manager.start_redis_listener(loop)
        admin_manager.start_redis_listener(loop)
        logger.info("[OK] Redis pub/sub listeners started (cross-pod WebSocket broadcasting enabled)")
    except Exception as e:
        logger.warning(f"[WARN] Redis pub/sub listeners not started: {e} — falling back to local broadcast")

    # ── Kafka consumer + broadcast task ───────────────────────────────────────
    result_queue = asyncio.Queue()
    broadcast_task = None

    if kafka_client.is_connected():
        loop = asyncio.get_running_loop()
        kafka_client.start_consumer(
            process_callback=process_raw_event,
            loop=loop,
            result_queue=result_queue,
        )
        logger.info("[OK] Kafka consumer started")

        async def broadcast_results():
            """
            Reads processed pipeline results from the queue and broadcasts them.

            With Redis: ws_manager.broadcast() publishes to Redis channel,
            which all pods receive and forward to their connected browsers.

            Without Redis: broadcasts only to browsers on THIS pod (original behavior).
            """
            while True:
                try:
                    result = await result_queue.get()
                    result_data = result.model_dump()

                    # Broadcast pipeline result to simulation dashboard
                    # (goes via Redis if available, local-only if not)
                    await ws_manager.broadcast({
                        "type": "pipeline_result",
                        "data": {
                            "event": result.event_summary,
                            "prediction": result_data,
                        }
                    })

                    # If this event created an admin alert, notify admin clients
                    alert_id = result.event_summary.get("alert_id")
                    if alert_id:
                        alert = admin_store.get_alert(alert_id)
                        if alert:
                            await admin_manager.broadcast({
                                "type": "new_alert",
                                "data": alert,
                            })

                except Exception as e:
                    logger.error(f"Broadcast error: {e}")

        broadcast_task = asyncio.create_task(broadcast_results())

    logger.info(f"\n  Pipeline ready. Serving on http://0.0.0.0:8000")
    logger.info(f"  Docs:  http://localhost:8000/docs")
    logger.info(f"{'='*60}\n")

    yield  # ── App runs here ──────────────────────────────────────────────────

    # ── Shutdown ───────────────────────────────────────────────────────────────
    logger.info("Shutting down HPE Pipeline...")

    try:
        from app import threat_engine
        threat_engine.flush_metrics_to_db()
    except Exception as e:
        logger.error(f"Failed to flush metrics on shutdown: {e}")

    try:
        from app import db
        db.close_pool()
    except Exception as e:
        logger.error(f"Failed to close DB pool: {e}")

    kafka_client.disconnect_kafka()

    if broadcast_task:
        broadcast_task.cancel()

    elastic_client.disconnect_elasticsearch()
    vault_client.disconnect_vault()

    logger.info("Shutdown complete.")


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title=APP_NAME,
    description=f"{APP_TAGLINE} — AI-Powered Network Threat Detection Pipeline",
    version=APP_VERSION,
    lifespan=lifespan,
)

# CORS — allow frontend dev server and Kubernetes ingress
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from app.routes import predict, health, pipeline, simulate, admin, auth

# Register routes
app.include_router(predict.router)
app.include_router(health.router)
app.include_router(pipeline.router)
app.include_router(simulate.router)
app.include_router(admin.router)
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])


@app.get("/")
async def root():
    """Root endpoint with app info."""
    return {
        "app": APP_NAME,
        "tagline": APP_TAGLINE,
        "version": APP_VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }