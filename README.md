

# 🎯 BeaconHunter - SOC C2 Beaconing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue)](https://reactjs.org)
[![MITRE](https://img.shields.io/badge/MITRE-T1071.001-red)](https://attack.mitre.org/techniques/T1071/001/)

## 🚀 Live Demo

- **Live Dashboard:** https://beaconhunter-dashboard.onrender.com
- **API Documentation:** https://beaconhunter.onrender.com/docs
- **Health Check:** https://beaconhunter.onrender.com/health
- **GitHub Repository:** https://github.com/Dhare2006/BeaconHunter

---

## 📊 What is BeaconHunter?

BeaconHunter is a **production-ready SOC (Security Operations Center) platform** that detects command-and-control (C2) beaconing patterns in real-time using statistical analysis.

### Features

- 🔴 **Critical Alert** - C2 Beaconing Detected (T1071.001) - Regular 60-second callback patterns
- 🟠 **Medium Alert** - Malware Distribution (T1595) - Connection to known malicious IPs
- 🟡 **Medium Alert** - Suspicious Domain (T1568.002) - Phishing/malware domain detection
- 🟡 **Medium Alert** - Suspicious User Agent (T1071) - Unusual HTTP user agents

---

## 🛠 Local Setup

### Prerequisites
- Python 3.11+
- Node.js 16+
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/Dhare2006/BeaconHunter.git
cd BeaconHunter
```

### Step 2: Backend Setup (Terminal 1)
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Step 3: Frontend Setup (Terminal 2)
```bash
cd frontend
npm install
npm run dev
```

### Step 4: Open Dashboard
```
http://localhost:5173
```

---

## 🔍 How Detection Works

### C2 Beaconing Detection (Critical)
```python
intervals = [60, 60, 60, 60]  # seconds between events
mean_interval = np.mean(intervals)    # 60.0
std_interval = np.std(intervals)      # 0.0

if std_interval < 5:
    alert = "C2 Beaconing Detected"
    mitre_technique = "T1071.001"
```

### IOC Detection (Medium)
- **Malicious IPs** → MITRE T1595
- **Suspicious Domains** → MITRE T1568.002
- **Bad User Agents** → MITRE T1071

---

## 🧪 Testing with Simulated Attacks

```bash
# Reset
curl -X DELETE https://beaconhunter.onrender.com/reset

# C2 Beaconing (Critical)
curl -X POST "https://beaconhunter.onrender.com/events/batch" -H "Content-Type: application/json" -d '[
  {"source_ip":"192.168.1.100","destination_ip":"45.67.23.11","protocol":"HTTPS","timestamp":"2026-06-06T10:00:00","domain":"evil-c2.com"},
  {"source_ip":"192.168.1.100","destination_ip":"45.67.23.11","protocol":"HTTPS","timestamp":"2026-06-06T10:01:00","domain":"evil-c2.com"},
  {"source_ip":"192.168.1.100","destination_ip":"45.67.23.11","protocol":"HTTPS","timestamp":"2026-06-06T10:02:00","domain":"evil-c2.com"},
  {"source_ip":"192.168.1.100","destination_ip":"45.67.23.11","protocol":"HTTPS","timestamp":"2026-06-06T10:03:00","domain":"evil-c2.com"}
]'

# Malicious IP (Medium)
curl -X POST "https://beaconhunter.onrender.com/events/batch" -H "Content-Type: application/json" -d '[
  {"source_ip":"10.0.0.5","destination_ip":"185.142.53.35","protocol":"HTTP","timestamp":"2026-06-06T10:05:00","domain":"malware-c2.net","user_agent":"curl/7.68.0"}
]'

# Suspicious Domain (Medium)
curl -X POST "https://beaconhunter.onrender.com/events/batch" -H "Content-Type: application/json" -d '[
  {"source_ip":"10.0.0.5","destination_ip":"8.8.8.8","protocol":"HTTPS","timestamp":"2026-06-06T10:06:00","domain":"phishing-bank.xyz"}
]'

# Run detection
curl -X POST https://beaconhunter.onrender.com/detect

# Check results
curl https://beaconhunter.onrender.com/stats
```

### Expected Output
```json
{
  "total_events": 6,
  "total_alerts": 3,
  "critical_alerts": 1,
  "medium_alerts": 2,
  "beaconing_detections": 1
}
```

---

## 📁 Project Structure
```
BeaconHunter/
├── backend/
│   ├── app/
│   │   └── main.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── App.css
│   └── package.json
└── README.md
```

---

## 📊 API Endpoints

- `GET /` - API information
- `GET /health` - Health check
- `GET /events` - Get all events
- `POST /events/batch` - Ingest events
- `POST /detect` - Run detection
- `GET /alerts` - Get all alerts
- `GET /stats` - Dashboard stats
- `DELETE /reset` - Reset data

---

## ⚠️ Ethical Disclaimer

> **This tool is for educational and defensive security research only.**

**✅ DO:**
- Use in your own isolated environment
- Test with permission on your infrastructure
- Learn about detection algorithms

**❌ DON'T:**
- Use without authorization
- Use for malicious purposes
- Target real systems

*All attacks shown are SIMULATED test data in isolated environment.*

---

## 🔗 Links

- **Live Dashboard:** https://beaconhunter-dashboard.onrender.com
- **API Docs:** https://beaconhunter.onrender.com/docs
- **GitHub:** https://github.com/Dhare2006/BeaconHunter

---

## 📝 License

MIT License - Free for educational and research use.

---

**Built with 🔒 for security research and education**
```

## 📤 How to Update

1. **Open** `C:/Users/Megavarthini/BeaconHunter/README.md`
2. **Select All** (Ctrl+A)
3. **Delete** everything
4. **Paste** the above code (Ctrl+V)
5. **Save** (Ctrl+S)
6. **Push to GitHub:**
```bash
git add README.md
git commit -m "Complete README"
git push origin main
```
