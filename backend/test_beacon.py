import requests
import json
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000"

def test_beaconing_detection():
    print("="*60)
    print("BeaconHunter Detection Engine Test")
    print("="*60)
    
    # Test 1: Health Check
    print("\n[TEST 1] Health Check")
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"✓ Status: {response.json()}")
    except Exception as e:
        print(f"✗ Error: {e}")
        print("Make sure backend is running on port 8000")
        return
    
    # Test 2: Create beaconing traffic
    print("\n[TEST 2] Creating C2 Beaconing Pattern (60-second intervals)")
    beacon_events = []
    for i in range(8):
        event = {
            "source_ip": "192.168.1.100",
            "destination_ip": "45.67.23.11",
            "protocol": "HTTPS",
            "timestamp": (datetime.now() + timedelta(seconds=i*60)).isoformat(),
            "bytes_sent": 1024,
            "bytes_received": 2048,
            "domain": "evil-c2.com",
            "user_agent": "Mozilla/5.0"
        }
        beacon_events.append(event)
    
    response = requests.post(f"{BASE_URL}/events/batch", json=beacon_events)
    print(f"✓ Ingested {len(beacon_events)} beaconing events")
    
    # Test 3: Run detection
    print("\n[TEST 3] Running Beaconing Detection")
    response = requests.post(f"{BASE_URL}/detect")
    result = response.json()
    print(f"✓ Detection complete - {result['alerts_generated']} alerts generated")
    
    # Test 4: Get alerts
    print("\n[TEST 4] Retrieving Alerts")
    response = requests.get(f"{BASE_URL}/alerts")
    alerts = response.json()
    print(f"✓ Total alerts: {len(alerts)}")
    for alert in alerts:
        print(f"  → [{alert['severity']}] {alert['alert_type']}")
        print(f"    {alert['description'][:80]}...")
        print(f"    MITRE: {alert.get('mitre_technique', 'N/A')}")
    
    # Test 5: Statistics
    print("\n[TEST 5] Dashboard Statistics")
    response = requests.get(f"{BASE_URL}/stats")
    stats = response.json()
    print(f"✓ Total Events: {stats['total_events']}")
    print(f"✓ Total Alerts: {stats['total_alerts']}")
    print(f"✓ Critical Alerts: {stats['critical_alerts']}")
    print(f"✓ High Alerts: {stats['high_alerts']}")
    print(f"✓ Beaconing Detections: {stats['beaconing_detections']}")
    print(f"✓ Unique IPs: {stats['unique_ips']}")
    
    print("\n" + "="*60)
    print("✅ Test completed successfully!")
    print("="*60)

if __name__ == "__main__":
    test_beaconing_detection()