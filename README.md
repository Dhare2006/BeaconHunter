# 🎯 BeaconHunter - SOC C2 Beaconing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue)](https://reactjs.org)
[![MITRE](https://img.shields.io/badge/MITRE-T1071.001-red)](https://attack.mitre.org/techniques/T1071/001/)

## 🚀 Live Demo

- **Dashboard:** https://beaconhunter-dashboard.onrender.com
- **API Documentation:** https://beaconhunter.onrender.com/docs
- **Health Check:** https://beaconhunter.onrender.com/health

## 📊 What is BeaconHunter?

BeaconHunter is a **production-ready SOC (Security Operations Center) platform** that detects command-and-control (C2) beaconing patterns in real-time using statistical analysis.

## 🛠 Tech Stack

- **FastAPI** - Python backend framework
- **React** - Frontend dashboard
- **PostgreSQL** - Database
- **Render** - Cloud deployment

## 🔗 Links

- **Live Dashboard:** https://beaconhunter-dashboard.onrender.com
- **API Docs:** https://beaconhunter.onrender.com/docs
- **GitHub:** https://github.com/Dhare2006/BeaconHunter

## 🔍 How Detection Works

The system uses statistical analysis to detect C2 beaconing:

```python
# Calculate time intervals between events
intervals = [60, 60, 60, 60]  # seconds

# Statistical analysis
mean_interval = np.mean(intervals)    # 60.0
std_interval = np.std(intervals)      # 0.0
cv = std_interval / mean_interval     # 0.0

if cv < 0.15:  # Highly regular pattern
    alert = "C2 Beaconing Detected"
    severity = "Critical"
    mitre_technique = "T1071.001"