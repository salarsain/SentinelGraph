"""
SentinelGraph — WebSocket API

Real-time scan progress updates via WebSocket.
Clients connect to /ws/scans/{scan_id} and receive JSON messages
as the scan progresses through phases.
"""


import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.redis import ScanProgressPublisher

logger = structlog.get_logger(__name__)
router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections per scan."""

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)
        logger.info("ws.connected", scan_id=scan_id)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].remove(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]
        logger.info("ws.disconnected", scan_id=scan_id)

    async def broadcast(self, scan_id: str, message: dict):
        """Send message to all connections watching a scan."""
        if scan_id in self.active_connections:
            dead = []
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead.append(connection)
            for conn in dead:
                self.disconnect(conn, scan_id)


manager = ConnectionManager()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(
    websocket: WebSocket,
    scan_id: str,
):
    """WebSocket endpoint for real-time scan progress.

    Clients receive JSON messages with scan status updates:
    ```json
    {
        "type": "progress",
        "scan_id": "uuid",
        "status": "running",
        "progress": 0.45,
        "current_phase": "crawling",
        "message": "Discovered 127 URLs"
    }
    ```
    """
    await manager.connect(websocket, scan_id)

    try:
        # Subscribe to Redis pub/sub for this scan
        publisher = ScanProgressPublisher()
        await publisher.subscribe(scan_id)

        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id,
            "message": "Connected to scan progress stream",
        })

        # Listen for Redis messages and forward to WebSocket
        while True:
            # Check for client messages (ping/disconnect)
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("ws.error", scan_id=scan_id, error=str(e))
    finally:
        manager.disconnect(websocket, scan_id)
