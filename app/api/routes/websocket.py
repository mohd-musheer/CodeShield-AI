import asyncio
import re
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.utils.progress import ProgressTracker

router = APIRouter(
    prefix="/ws",
    tags=["WebSockets"],
)


@router.websocket("/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint to subscribe to real-time scan progress updates."""
    if not re.match(r"^[\w\-]+$", scan_id):
        await websocket.accept()
        await websocket.send_json({"error": "Invalid scan ID format"})
        await websocket.close()
        return

    await websocket.accept()
    tracker = ProgressTracker()
    tracker.register_websocket(websocket)
    
    try:
        last_percent = -1
        last_status = ""
        while True:
            # Retrieve current progress state (which now includes stages)
            progress = tracker.get_progress(scan_id)
            status = progress.get("status", "unknown")
            percent = progress.get("percent", 0)

            # Send progress update if it has changed
            if percent != last_percent or status != last_status:
                await websocket.send_json({
                    "scan_id": scan_id,
                    **progress
                })
                last_percent = percent
                last_status = status

            if status in ["completed", "failed", "cancelled"]:
                # Let the client read the final completion packet before closing
                await asyncio.sleep(0.5)
                break

            # Poll progress status every 250ms for responsive updates
            await asyncio.sleep(0.25)
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"error": str(e)})
        except Exception:
            pass
    finally:
        tracker.unregister_websocket(websocket)
        try:
            await websocket.close()
        except Exception:
            pass
