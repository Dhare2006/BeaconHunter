from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict
from datetime import datetime, timedelta, timezone
from pydantic import BaseModel
from collections import defaultdict
import numpy as np
import uuid

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

class Alert(BaseModel):
    id: str
    timestamp: datetime
    alert_type: str
    severity: str
    score: int
    source_ip: str
    destination_ip: str
    description: str
    mitre_technique: Optional[str] = None
    confidence: str

# ============ APP SETUP ============

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",  # Allow all origins temporarily
        "https://beaconhunter-dashboard.onrender.com",
        "http://localhost:5173",
        "https://beaconhunter.onrender.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ DATABASE ============

events_db = []
alerts_db = []

# ============ DETECTION ENGINE ============

from datetime import timezone

def detect_beaconing_pattern(events: List[Dict]) -> Optional[Dict]:
    """Detect regular beaconing patterns using statistical analysis"""
    
    if len(events) < 4:
        return None
    
    # Helper function to ensure all timestamps are timezone-aware
    def ensure_timezone_aware(dt):
        if dt.tzinfo is None:
            # If naive, assume UTC
            return dt.replace(tzinfo=timezone.utc)
        return dt
    
    # Sort by timestamp with timezone handling
    sorted_events = sorted(events, key=lambda x: ensure_timezone_aware(x['timestamp']))
    
    # Calculate intervals
    intervals = []
    for i in range(1, len(sorted_events)):
        t1 = ensure_timezone_aware(sorted_events[i-1]['timestamp'])
        t2 = ensure_timezone_aware(sorted_events[i]['timestamp'])
        interval = (t2 - t1).total_seconds()
        intervals.append(interval)
    
    if len(intervals) < 3:
        return None
    
    # Statistical analysis
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    cv = std_interval / mean_interval if mean_interval > 0 else 1
    
    # Beaconing detection logic
    if cv < 0.15:  # Very regular pattern
        return {
            "alert_type": "C2 Beaconing Detected",
            "severity": "Critical",
            "score": 95,
            "confidence": "High",
            "description": f"Highly regular beaconing every {mean_interval:.1f} seconds (variance: {std_interval:.1f}s)",
            "mitre_technique": "T1071.001 - Application Layer Protocol: Web Protocols",
            "details": {
                "mean_interval": round(mean_interval, 2),
                "std_deviation": round(std_interval, 2),
                "coefficient_variation": round(cv, 3),
                "sample_size": len(intervals)
            }
        }
    elif cv < 0.30:  # Somewhat regular pattern
        return {
            "alert_type": "Potential Beaconing",
            "severity": "High",
            "score": 75,
            "confidence": "Medium",
            "description": f"Regular communication pattern detected every ~{mean_interval:.1f} seconds",
            "mitre_technique": "T1071 - Application Layer Protocol",
            "details": {
                "mean_interval": round(mean_interval, 2),
                "std_deviation": round(std_interval, 2),
                "coefficient_variation": round(cv, 3)
            }
        }
    
    return None

def check_iocs(event: Dict) -> int:
    """Check event against known IOCs"""
    score = 0
    
    # Known malicious IPs
    malicious_ips = {
        "45.67.23.11": 30,
        "185.142.53.35": 25,
        "103.25.13.55": 20
    }
    
    # Check destination IP
    dest_ip = event.get('destination_ip')
    if dest_ip and dest_ip in malicious_ips:
        score += malicious_ips[dest_ip]
    
    # Suspicious domains
    domain = event.get('domain')
    if domain and isinstance(domain, str):
        domain_lower = domain.lower()
        if any(bad in domain_lower for bad in ['evil', 'c2', 'malware', 'phishing']):
            score += 25
    
    # Suspicious user agents (FIXED - handles None properly)
    ua = event.get('user_agent')
    if ua and isinstance(ua, str):
        ua_lower = ua.lower()
        if any(bot in ua_lower for bot in ['curl', 'wget', 'python']):
            score += 20
    
    return min(score, 100)

# ============ API ENDPOINTS ============

@app.get("/")
def root():
    return {
        "name": "BeaconHunter",
        "status": "operational",
        "version": "1.0.0",
        "endpoints": [
            "POST /events - Ingest network event",
            "POST /events/batch - Batch ingest",
            "GET /events - Get events",
            "POST /detect - Run detection",
            "GET /alerts - Get alerts",
            "GET /stats - Get statistics"
        ]
    }

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now()}

@app.post("/events")
async def ingest_event(event: NetworkEvent):
    """Ingest a single network event"""
    event_dict = event.dict()
    event_dict['id'] = len(events_db)
    event_dict['ingested_at'] = datetime.now()
    events_db.append(event_dict)
    
    return {
        "message": "Event ingested",
        "event_id": event_dict['id'],
        "total_events": len(events_db)
    }

@app.post("/events/batch")
async def ingest_batch(events: List[NetworkEvent]):
    """Ingest multiple events at once"""
    for event in events:
        event_dict = event.dict()
        event_dict['id'] = len(events_db)
        event_dict['ingested_at'] = datetime.now()
        events_db.append(event_dict)
    
    return {
        "message": f"Ingested {len(events)} events",
        "total_events": len(events_db)
    }

@app.get("/events")
async def get_events(limit: int = 100, dest_ip: Optional[str] = None):
    """Get recent events"""
    events = events_db[-limit:]
    if dest_ip:
        events = [e for e in events if e['destination_ip'] == dest_ip]
    return events

@app.post("/detect")
async def run_detection():
    """Run beaconing detection on all events"""
    new_alerts = []
    
    # Group events by destination IP
    grouped = defaultdict(list)
    for event in events_db:
        grouped[event['destination_ip']].append(event)
    
    # Analyze each destination
    for dest_ip, events in grouped.items():
        # Check for beaconing pattern
        beacon_alert = detect_beaconing_pattern(events)
        if beacon_alert:
            alert = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(),
                "source_ip": events[0]['source_ip'],
                "destination_ip": dest_ip,
                **beacon_alert
            }
            alerts_db.append(alert)
            new_alerts.append(alert)
        
        # Check individual events for IOCs
        for event in events:
            ioc_score = check_iocs(event)
            if ioc_score >= 30:
                alert = {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now(),
                    "alert_type": "IOC Match",
                    "severity": "High" if ioc_score >= 70 else "Medium",
                    "score": ioc_score,
                    "source_ip": event['source_ip'],
                    "destination_ip": event['destination_ip'],
                    "description": f"IOC detected: {event.get('domain', event['destination_ip'])}",
                    "mitre_technique": "T1595 - Active Scanning",
                    "confidence": "High"
                }
                alerts_db.append(alert)
                new_alerts.append(alert)
    
    return {
        "message": f"Detection complete",
        "alerts_generated": len(new_alerts),
        "alerts": new_alerts
    }

@app.get("/alerts")
async def get_alerts(severity: Optional[str] = None, limit: int = 100):
    """Get alerts"""
    alerts = alerts_db[-limit:]
    if severity:
        alerts = [a for a in alerts if a['severity'].lower() == severity.lower()]
    return alerts

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    severity_counts = defaultdict(int)
    for alert in alerts_db:
        severity_counts[alert['severity']] += 1
    
    return {
        "total_events": len(events_db),
        "total_alerts": len(alerts_db),
        "critical_alerts": severity_counts.get("Critical", 0),
        "high_alerts": severity_counts.get("High", 0),
        "medium_alerts": severity_counts.get("Medium", 0),
        "low_alerts": severity_counts.get("Low", 0),
        "beaconing_detections": len([a for a in alerts_db if "Beaconing" in a['alert_type']]),
        "unique_ips": len(set(e['destination_ip'] for e in events_db))
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)