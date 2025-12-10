from flask import Flask, request, jsonify, render_template
import os
import sqlite3
import json
from datetime import datetime
import zipfile
from apk_analyzer import APKAnalyzer
from app_database import db
from livereload import Server

# Init
app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['MAX_CONTENT_LENGTH'] = 230 * 1024 * 1024  # 100 MB
app.jinja_env.auto_reload = True
db.init_database()

# Configuration
UPLOAD_FOLDER = '../uploads'
DATABASE = '../../database/app.db'
MAX_FILES = 3
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('../../database', exist_ok=True)

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
@app.route('/')
def index():
    return render_template('index.html')

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

        # Query the correct columns from your store_scan_result function
        cursor.execute('''
            SELECT id, file_info, apk_metadata, ml_prediction_result, analysis_timestamp 
            FROM scans 
            ORDER BY analysis_timestamp DESC 
        ''')

        scans = []
        for row in cursor.fetchall():
            scan = {
                'id': row[0],
                'file_info': json.loads(row[1]) if row[1] else {},
                'apk_metadata': json.loads(row[2]) if row[2] else {},
                'ml_prediction_result': json.loads(row[3]) if row[3] else {},
                'analysis_timestamp': row[4]
            }
            scans.append(scan)

        conn.close()
        return jsonify(scans)  # Return array directly, not {'scans': scans}

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Query all the columns you store in store_scan_result
        cursor.execute('''
            SELECT file_info, apk_metadata, certificate_info, permissions, 
                   flags, ml_prediction_result, analysis_timestamp 
            FROM scans WHERE id = ?
        ''', (scan_id,))
        
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Scan not found'}), 404

        # Return the exact structure your frontend expects
        analysis_result = {
            'file_info': json.loads(row[0]) if row[0] else {},
            'apk_metadata': json.loads(row[1]) if row[1] else {},
            'certificate_info': json.loads(row[2]) if row[2] else {},
            'permissions': json.loads(row[3]) if row[3] else {},
            'flags': json.loads(row[4]) if row[4] else {},
            'ml_prediction_result': json.loads(row[5]) if row[5] else {},
            'analysis_timestamp': row[6]
        }

        conn.close()
        return jsonify(analysis_result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    server = Server(app.wsgi_app)
    server.watch("templates/*.html")   # auto-reload on HTML changes
    server.watch("static/*.*")         # auto-reload on CSS/JS changes
    server.serve(host="0.0.0.0", port=5000, debug=True)