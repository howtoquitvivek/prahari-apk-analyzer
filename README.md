# 🛡️ FakeAPK Guardian - Banking App Security Scanner

A comprehensive cybersecurity tool for detecting fake banking APKs using static analysis and machine learning.

## Quick Start

### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python database.py  # Initialize database
python app.py       # Start Flask server
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## Features
- APK Static Analysis
- ML-based Fake Detection
- Risk Scoring (0-100)
- Real-time Dashboard
- Scan History

## Usage
1. Start both backend and frontend servers
2. Open http://localhost:3000
3. Upload APK file for analysis
4. View comprehensive security report

## Tech Stack
- Backend: Python Flask + SQLite
- Frontend: HTML/CSS/JS + Vite
- ML: scikit-learn Random Forest
