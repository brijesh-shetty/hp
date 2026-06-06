"""
simulate.py — WebSocket endpoint to stream test events to the frontend.
Maintains a global event index so the simulation continues from where it
left off even when the frontend reconnects.
"""

import json
import asyncio
import random
import logging
from pathlib import Path
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config import TEST_EVENTS_PATH
from app.schemas import NetworkEvent
from app.threat_engine import process_event
from app import kafka_client
from app import db
from app.ws_manager import manager as ws_manager

logger = logging.getLogger("hpe.simulate")
router = APIRouter(tags=["simulation"])

# In-memory cache for test events
_test_events = None

# Global simulation position — persists across frontend reconnects
_sim_index = 0
_sim_batch_count = 0
_SIM_BATCH_SIZE = 10

def _load_sim_index():
    global _sim_index
    try:
        row = db.execute_query("SELECT sim_index FROM hpe_simulation_state WHERE id = 1", fetch=True)
        if row:
            _sim_index = row.get("sim_index", 0)
    except Exception as e:
        logger.error(f"Failed to load sim_index: {e}")

def _save_sim_index():
    global _sim_index, _sim_batch_count
    _sim_batch_count += 1
    if _sim_batch_count >= _SIM_BATCH_SIZE:
        try:
            db.execute_query("UPDATE hpe_simulation_state SET sim_index = %s WHERE id = 1", (_sim_index,))
            _sim_batch_count = 0
        except Exception as e:
            logger.error(f"Failed to save sim_index: {e}")

def _load_test_events():
    global _test_events
    path = Path(TEST_EVENTS_PATH)
    if not path.exists():
        logger.error(f"Test events file not found: {TEST_EVENTS_PATH}")
        _test_events = []
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            _test_events = json.load(f)
        logger.info(f"Loaded {len(_test_events)} test events for simulation")
    except Exception as e:
        logger.error(f"Failed to load test events: {e}")
        _test_events = []

@router.websocket("/ws/simulate")
async def simulate_stream(websocket: WebSocket):
    """
    WebSocket endpoint that sequentially streams the test events.
    Resumes from the last position if the frontend reconnects.
    Loops continuously through the dataset.
    """
    global _sim_index
    await websocket.accept()

    if _test_events is None:
        _load_test_events()

    _load_sim_index()

    total = len(_test_events)
    if total == 0:
        await websocket.send_json({
            "type": "error",
            "data": {"message": "No test events loaded"},
        })
        return

    # Determine server location
    server_info = {"lat": 12.97, "lng": 77.59, "city": "Bangalore"}

    # Send server info first
    await websocket.send_json({
        "type": "server_info",
        "data": server_info,
    })

    # Tell the frontend where we're resuming from
    await websocket.send_json({
        "type": "simulation_status",
        "data": {
            "resuming_from": _sim_index,
            "total_events": total,
            "message": f"Resuming simulation from event {_sim_index}/{total}"
        },
    })

    # Register this WebSocket to receive broadcast results
    ws_manager.add(websocket)

    try:
        # Loop continuously through events
        while True:
            raw_event = _test_events[_sim_index % total]

            try:
                if kafka_client.is_connected():
                    kafka_client.produce_raw_event({
                        "event_id": str(uuid.uuid4())[:12],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        **raw_event,
                    })
                    kafka_client.flush()  # Ensure delivery
                else:
                    # Fallback if Kafka is down
                    event = NetworkEvent(**{k: v for k, v in raw_event.items()
                                        if k in NetworkEvent.model_fields})
                    result = process_event(event)

                    # Send the full result
                    await websocket.send_json({
                        "type": "pipeline_result",
                        "data": {
                            "event": raw_event,
                            "prediction": result.model_dump(),
                        }
                    })

            except Exception as e:
                logger.error(f"Simulation event error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "data": {"message": str(e)},
                })

            # Advance global position
            _sim_index += 1
            _save_sim_index()

            # Log when a full cycle completes
            if _sim_index > 0 and _sim_index % total == 0:
                logger.info(f"Simulation completed cycle {_sim_index // total}, looping...")

            # Random delay between events (2.0s - 5.0s)
            delay = random.uniform(2.0, 5.0)
            await asyncio.sleep(delay)

    except WebSocketDisconnect:
        ws_manager.remove(websocket)
        logger.info(f"WebSocket client disconnected. Simulation paused at event {_sim_index}")
    except Exception as e:
        ws_manager.remove(websocket)
        logger.error(f"WebSocket error: {e}")

@router.get("/api/sample-events")
async def get_sample_events():
    """Get the loaded sample events (for frontend initialization)."""
    if _test_events is None:
        _load_test_events()

    return {
        "test_events_count": len(_test_events)
    }
