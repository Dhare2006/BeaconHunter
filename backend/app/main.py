from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from collections import defaultdict
import numpy as np
import uuid

# ============ CREATE FASTAPI APP ============
app = FastAPI(title="BeaconHunter", version="1.0.0")

# ============ CORS MIDDLEWARE ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ DATABASE (In-Memory) ============
events_db = []
alerts_db = []

# ============ MODELS ============
class NetworkEvent(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    timestamp: datetime
    bytes_sent: int = 0
    bytes_received: int = 0
    domain: Optional[str] = None
    user_agent: Optional[str] = None

# ============ DETECTION ENGINE ============
def detect_c2_beaconing(events):
    """Detect C2 beaconing patterns using statistical analysis"""
    
    if len(events) < 4:
        return None
    
    # Extract and sort timestamps
    timestamps = [e['timestamp'] for e in events]
    timestamps.sort()
    
    # Calculate time intervals between events
    intervals = []
    for i in range(1, len(timestamps)):
        interval = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(interval)
    
    if len(intervals) < 3:
        return None
    
    # Statistical analysis
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    
    # Beaconing detection logic
    # Regular intervals with low standard deviation = C2 beaconing
    if std_interval < 5 and mean_interval >= 30:
        return {
            "alert_type": "C2 Beaconing Detected",
            "severity": "Critical",
            "score": 95,
            "confidence": "High",
            "description": f"Regular beaconing pattern - events every {mean_interval:.0f} seconds (std: {std_interval:.1f}s)",
            "mitre_technique": "T1071.001"
        }
    elif std_interval < 15 and mean_interval >= 30:
        return {
            "alert_type": "Potential C2 Beaconing",
            "severity": "High",
            "score": 75,
            "confidence": "Medium",
            "description": f"Potential beaconing pattern - approx every {mean_interval:.0f} seconds",
            "mitre_technique": "T1071"
        }
    
    return None

# ============ API ENDPOINTS ============
@app.get("/")
def root():
    return {
        "name": "BeaconHunter",
        "status": "operational",
        "version": "1.0.0"
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now()}

@app.post("/events/batch")
async def ingest_batch(events: List[NetworkEvent]):
    """Ingest multiple network events"""
    for event in events:
        events_db.append(event.dict())
    return {
        "message": f"Ingested {len(events)} events",
        "total_events": len(events_db)
    }

@app.post("/detect")
async def run_detection():
    """Run C2 beaconing detection on all events"""
    
    if len(events_db) < 4:
        return {
            "message": "Need at least 4 events for detection",
            "alerts_generated": 0,
            "total_events": len(events_db)
        }
    
    # Group events by destination IP
    grouped = defaultdict(list)
    for event in events_db:
        grouped[event['destination_ip']].append(event)
    
    new_alerts = []
    for dest_ip, evts in grouped.items():
        alert_data = detect_c2_beaconing(evts)
        if alert_data:
            alert = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(),
                "source_ip": evts[0]['source_ip'],
                "destination_ip": dest_ip,
                **alert_data
            }
            alerts_db.append(alert)
            new_alerts.append(alert)
    
    return {
        "message": "Detection complete",
        "alerts_generated": len(new_alerts),
        "total_events": len(events_db),
        "total_alerts": len(alerts_db)
    }

@app.get("/alerts")
async def get_alerts():
    """Get all security alerts"""
    return alerts_db

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    critical = sum(1 for a in alerts_db if a.get('severity') == 'Critical')
    high = sum(1 for a in alerts_db if a.get('severity') == 'High')
    beaconing = sum(1 for a in alerts_db if 'Beaconing' in a.get('alert_type', ''))
    
    return {
        "total_events": len(events_db),
        "total_alerts": len(alerts_db),
        "critical_alerts": critical,
        "high_alerts": high,
        "beaconing_detections": beaconing,
        "unique_ips": len(set(e['destination_ip'] for e in events_db))
    }

@app.delete("/reset")
async def reset_all():
    """Reset all data (for testing)"""
    global events_db, alerts_db
    events_db = []
    alerts_db = []
    return {"message": "All data cleared", "events": 0, "alerts": 0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)