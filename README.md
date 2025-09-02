
# 🛡️ Prahari - Malicious Banking APK Detector

A comprehensive cybersecurity tool for detecting fake banking APKs used for fraud using static analysis and machine learning.

## Quick Start

### Backend Setup
```bash
# Go to backend folder
cd backend

# Create and activate a virtual environment using uv
uv venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate

# Install dependencies
uv pip install -r requirements.txt

# Initialize the database
python database.py

# Start the Flask server (serves both backend API and frontend template)
python app.py

```



## Features
- APK Static Analysis
- ML-based Fake Detection
- Risk Scoring (0-100)
- Real-time Dashboard
- Scan History

## Usage
1. Start the Flask backend server
2. Open [http://localhost:5000](http://localhost:5000) in your browser.
3. Upload an APK file for analysis.
4. View the comprehensive security report directly on the same page.

## Tech Stack
- Backend: Python Flask + SQLite
- Frontend: Jinja2 templates + Tailwind
- ML: scikit-learn Logistic Regression, XGBClassifier

