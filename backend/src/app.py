from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import sqlite3
import json
from datetime import datetime
import zipfile
from apk_analyzer import APKAnalyzer
from app_database import db

app = Flask(__name__)
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
UPLOAD_FOLDER = '../uploads'
DATABASE = '../../database/app.db'
MAX_FILES = 3
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('../../database', exist_ok=True)

# Initialize database
db.init_database()


# Utils
def store_scan_result(analysis_result):
    """Store scan result in database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    file_info = analysis_result.get("file_info", {})
    apk_metadata = analysis_result.get("apk_metadata", {})
    certificate_info = analysis_result.get("certificate_info", {})
    permissions = analysis_result.get("permissions", {})
    flags = analysis_result.get("flags", {})
    ml_prediction_result = analysis_result.get("ml_prediction_result", {})
    analysis_timestamp = analysis_result.get("analysis_timestamp")

    cursor.execute('''
        INSERT INTO scans (
            file_info,
            apk_metadata,
            certificate_info,
            permissions,
            flags,
            ml_prediction_result,
            analysis_timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        json.dumps(file_info),
        json.dumps(apk_metadata),
        json.dumps(certificate_info),
        json.dumps(permissions),
        json.dumps(flags),
        json.dumps(ml_prediction_result),
        str(analysis_timestamp)  # ✅ always string
    ))

    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def maintain_limit(folder, max_files):
    files = sorted(
        [os.path.join(folder, f) for f in os.listdir(folder)],
        key=os.path.getctime  # sort by creation time
    )
    while len(files) >= max_files:
        os.remove(files[0])  # delete oldest
        files.pop(0)

# Routes
@app.route('/api/upload', methods=['POST'])
def upload_apk():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '' or not file.filename.endswith('.apk'):
            return jsonify({'error': 'Invalid APK file extension'}), 400

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        maintain_limit(UPLOAD_FOLDER, MAX_FILES)

        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        if not zipfile.is_zipfile(filepath):
            os.remove(filepath)
            return jsonify({'error': 'Uploaded file is not a valid APK'}), 400

        analyzer = APKAnalyzer(filepath)
        try:
            analysis_result = analyzer.analyze()
        except Exception as e:
            os.remove(filepath)
            return jsonify({'error': f'APK analysis failed: {str(e)}'}), 500

        scan_id = store_scan_result(analysis_result)

        # ✅ Fix: pull timestamp from root, not file_info
        return jsonify({
            "scan_id": scan_id,
            "analysis": analysis_result,

        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans', methods=['GET'])
def get_scan_history():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, filename, risk_score, is_fake, timestamp 
            FROM scans 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')

        scans = []
        for row in cursor.fetchall():
            scans.append({
                'id': row[0],
                'filename': row[1],
                'risk_score': row[2],
                'is_fake': row[3],
                'timestamp': row[4]
            })

        conn.close()
        return jsonify({'scans': scans})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()

        if not scan:
            return jsonify({'error': 'Scan not found'}), 404

        conn.close()
        return jsonify({
            'id': scan[0],
            'is_fake': scan[3],
            'analysis_data': json.loads(scan[4]),  # load back as dict
            'timestamp': scan[5]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
