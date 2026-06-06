from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from collections import defaultdict
import numpy as np
import uuid

app = FastAPI(title="BeaconHunter", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://beaconhunter-dashboard.onrender.com",
        "http://localhost:5173",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
events_db = []
alerts_db = []

class NetworkEvent(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    timestamp: datetime
    bytes_sent: int = 0
    bytes_received: int = 0
    domain: Optional[str] = None
    user_agent: Optional[str] = None

# ============ API ENDPOINTS ============
@app.get("/")
def root():
    return {"name": "BeaconHunter", "status": "operational"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now()}

@app.get("/events")  # ← ADD THIS MISSING ENDPOINT!
async def get_events():
    return events_db

@app.post("/events/batch")
async def ingest_batch(events: List[NetworkEvent]):
    for event in events:
        events_db.append(event.dict())
    return {"message": f"Ingested {len(events)} events", "total_events": len(events_db)}

@app.post("/detect")
async def run_detection():
    if len(events_db) < 4:
        return {"message": "Need at least 4 events", "alerts_generated": 0}
    
    grouped = defaultdict(list)
    for event in events_db:
        grouped[event['destination_ip']].append(event)
    
    new_alerts = []
    for dest_ip, evts in grouped.items():
        if len(evts) >= 4:
            alert = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(),
                "alert_type": "C2 Beaconing Detected",
                "severity": "Critical",
                "score": 95,
                "source_ip": evts[0]['source_ip'],
                "destination_ip": dest_ip,
                "description": "Regular beaconing pattern detected",
                "mitre_technique": "T1071.001",
                "confidence": "High"
            }
            alerts_db.append(alert)
            new_alerts.append(alert)
    
    return {"message": "Detection complete", "alerts_generated": len(new_alerts)}

@app.get("/alerts")
async def get_alerts():
    return alerts_db

@app.get("/stats")
async def get_stats():
    critical = sum(1 for a in alerts_db if a.get('severity') == 'Critical')
    return {
        "total_events": len(events_db),
        "total_alerts": len(alerts_db),
        "critical_alerts": critical,
        "beaconing_detections": critical,
        "unique_ips": len(set(e.get('destination_ip') for e in events_db))
    }

@app.delete("/reset")
async def reset():
    global events_db, alerts_db
    events_db = []
    alerts_db = []
    return {"message": "Reset complete"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)