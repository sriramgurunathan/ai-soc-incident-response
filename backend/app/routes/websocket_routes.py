import asyncio
import json
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        payload = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                disconnected.append(connection)
        for dead in disconnected:
            self.disconnect(dead)

ws_manager = ConnectionManager()

@router.websocket("/ws/soc-stream")
async def websocket_soc_stream(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Welcome telemetry packet
        await websocket.send_json({
            "type": "SYSTEM_CONNECTED",
            "message": "Connected to ApexShield Real-Time SOC Event Bus",
            "active_analysts": len(ws_manager.active_connections)
        })
        while True:
            # Keep alive and receive analyst messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
