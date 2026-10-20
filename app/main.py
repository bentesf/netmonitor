import asyncio
import logging
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from app.database import (
    init_db, get_devices, get_alerts, get_stats, 
    get_device_by_mac, delete_device, get_device_by_ip
)
from app.collectors.syslog_server import start_syslog_server
from app.collectors.snmp_poller import RealSNMPPoller
from app.collectors.network_scanner import LocalNetworkScanner
from app.collectors.nmap_scanner import NmapDeviceScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("NetMonitorMain")

app = FastAPI(title="NetMonitor - Enterprise VLAN Security Tool", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# WebSocket Connection Manager for real-time dashboard updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.on_event("startup")
async def startup_event():
    # Initialize SQLite database
    init_db()
    
    # 1. Start Syslog UDP listener on port 5140 (or 514 in root mode)
    syslog_port = int(os.getenv("SYSLOG_PORT", 5140))
    asyncio.create_task(start_syslog_server(port=syslog_port))
    
    # 2. Start background SNMP poller connected to Intelbras switch (172.128.100.8)
    poller = RealSNMPPoller(target_ip="172.128.100.8", user="sw", password="Summer01")
    asyncio.create_task(poller.run_periodic_polling(interval_seconds=120))
    
    # 3. Start local network ARP & subnet scanner collector
    scanner = LocalNetworkScanner()
    asyncio.create_task(scanner.run_periodic_scan(interval_seconds=45))
    
    logger.info("NetMonitor inicializado e conectando aos coletores de rede (SNMP, Syslog, Scanner ARP e Nmap).")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    index_file = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(index_file)

@app.get("/api/devices")
async def api_get_devices():
    return get_devices()

@app.get("/api/devices/{mac}")
async def api_get_device_detail(mac: str):
    dev = get_device_by_mac(mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado")
    return dev

@app.post("/api/devices/{ip}/scan")
async def api_scan_device(ip: str):
    """Executa varredura de portas e serviços Nmap no IP informado"""
    result = await NmapDeviceScanner.scan_device(ip)
    await manager.broadcast({"type": "NMAP_SCAN_COMPLETED", "ip": ip, "open_ports_count": result["open_ports_count"]})
    return result

@app.delete("/api/devices/{mac}")
async def api_delete_device(mac: str):
    success = delete_device(mac)
    if not success:
        raise HTTPException(status_code=404, detail="Dispositivo não encontrado para remoção")
    await manager.broadcast({"type": "DEVICE_DELETED", "mac": mac})
    return {"status": "ok", "message": f"Dispositivo {mac} removido com sucesso"}

@app.get("/api/alerts")
async def api_get_alerts():
    return get_alerts()

@app.get("/api/stats")
async def api_get_stats():
    return get_stats()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
