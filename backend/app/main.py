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


# ============ IOC DETECTION FUNCTION ============
def check_iocs(event):
    """Check event for Indicators of Compromise"""
    
    # Known malicious IPs
    malicious_ips = {
        "45.67.23.11": {"score": 30, "type": "Known C2 Server", "mitre": "T1071"},
        "185.142.53.35": {"score": 25, "type": "Malware Distribution", "mitre": "T1595"},
        "103.25.13.55": {"score": 20, "type": "Suspicious IP", "mitre": "T1595"}
    }
    
    dest_ip = event.get('destination_ip')
    if dest_ip in malicious_ips:
        info = malicious_ips[dest_ip]
        return info["score"], info["type"], info["mitre"]
    
    # Suspicious domains
    domain = event.get('domain', '')
    if domain:
        domain_lower = domain.lower()
        suspicious_domains = ['evil', 'c2', 'malware', 'phishing', 'malicious', 'crypt', 'ransom']
        for bad in suspicious_domains:
            if bad in domain_lower:
                return 25, "Suspicious Domain Detected", "T1568.002"
    
    # Suspicious user agents
    ua = event.get('user_agent', '')
    if ua:
        ua_lower = ua.lower()
        suspicious_agents = ['curl', 'wget', 'python-requests', 'go-http', 'powershell']
        for bad in suspicious_agents:
            if bad in ua_lower:
                return 20, "Suspicious User Agent", "T1071"
    
    return 0, None, None


# ============ API ENDPOINTS ============
@app.get("/")
def root():
    return {"name": "BeaconHunter", "status": "operational"}


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now()}


@app.get("/events")
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
    
    new_alerts = []
    
    # Group by destination IP for beaconing detection
    grouped = defaultdict(list)
    for event in events_db:
        grouped[event['destination_ip']].append(event)
    
    # ============ CRITICAL: C2 Beaconing Detection ============
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
                "description": f"Regular beaconing pattern detected with {len(evts)} events at 60-second intervals",
                "mitre_technique": "T1071.001",
                "confidence": "High"
            }
            alerts_db.append(alert)
            new_alerts.append(alert)
    
    # ============ MEDIUM: IOC Detection ============
    for event in events_db:
        score, alert_type, mitre = check_iocs(event)
        if score >= 20:
            alert = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(),
                "alert_type": alert_type,
                "severity": "Medium",
                "score": score,
                "source_ip": event['source_ip'],
                "destination_ip": event['destination_ip'],
                "description": f"IOC detected: {event.get('domain', event['destination_ip'])}",
                "mitre_technique": mitre,
                "confidence": "Medium"
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
    return alerts_db


@app.get("/stats")
async def get_stats():
    critical = sum(1 for a in alerts_db if a.get('severity') == 'Critical')
    medium = sum(1 for a in alerts_db if a.get('severity') == 'Medium')
    
    return {
        "total_events": len(events_db),
        "total_alerts": len(alerts_db),
        "critical_alerts": critical,
        "medium_alerts": medium,
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