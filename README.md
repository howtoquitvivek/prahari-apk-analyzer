# 🛡️ **PRAHARI — Malicious Banking APK Detector**

### *AI-Powered Static Analysis for Detecting Fraudulent Banking Apps*

Prahari is a cybersecurity tool built to identify **fake or malicious banking APKs** using **static APK analysis**, **machine learning**, and a clean **web dashboard**.
It extracts certificates, permissions, package metadata, and behavioral indicators, then predicts the probability of the APK being malicious.

---

# 📁 **Project Structure**

Your exact directory tree (simplified & readable):

```
prahari-apk-analyzer/
│
├── backend/
│   ├── ml_data/                      # Training/testing CSV feature datasets
│   │   ├── certificates_train.csv
│   │   ├── certificates_test.csv
│   │   ├── packages_train.csv
│   │   ├── packages_test.csv
│   │   ├── permissions_train.csv
│   │   └── permissions_test.csv
│   │
│   ├── src/
│   │   ├── models/                   # Trained ML models
│   │   │   ├── certificate_model.pkl
│   │   │   ├── certificate_vectorizer.pkl
│   │   │   ├── package_dictvec.pkl
│   │   │   ├── package_model.pkl
│   │   │   ├── package_scaler.pkl
│   │   │   ├── package_vectorizer.pkl
│   │   │   ├── permission_encoder.pkl
│   │   │   └── permission_model.pkl
│   │   │
│   │   ├── templates/                # Jinja2 HTML templates
│   │   │   └── index.html
│   │   │
│   │   ├── apk_analyzer.py           # APK feature extraction logic
│   │   ├── app_database.py           # SQLite DB functions
│   │   ├── app.py                    # 🔥 Main Flask API + Web UI
│   │   ├── ml_classes.py             # ML pipeline classes
│   │   └── utils.py                  # Helper utilities
│   │
│   └── uploads/                      # Uploaded APKs (ignored in Git)
│
├── database/
│   └── app.db                        # SQLite database
│
├── datagen/                           # Dataset generation scripts
│   ├── all_feats/
│   │   ├── all_feat_fake.json
│   │   └── all_feat_real.json
│   ├── output/                        # Generated ML-ready feature CSVs
│   │   ├── certificates_train.csv
│   │   ├── certificates_test.csv
│   │   ├── packages_train.csv
│   │   ├── packages_test.csv
│   │   ├── permissions_train.csv
│   │   └── permissions_test.csv
│   ├── utils/
│   │   └── rem_dup.py
│   ├── certificates.py
│   ├── packages.py
│   └── permissions.py
│
├── docs/
│   ├── prahari_deck1.pdf
│   └── prahari_synopsis.pdf
│
├── venv/                             # Python virtual environment (ignored)
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

# 🚀 **Installation Guide**

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/<your-username>/prahari-apk-analyzer.git
cd prahari-apk-analyzer
```

---

## 2️⃣ Create a Python Virtual Environment

```bash
python -m venv venv
```

### Activate it:

**Linux/macOS**

```bash
source venv/bin/activate
```

**Windows (PowerShell):**

```bash
venv\Scripts\activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Run the Backend Server

Navigate to the backend source:

```bash
cd backend/src
```

Start Flask:

```bash
python app.py
```

Your dashboard is live at:

👉 **[http://localhost:5000](http://localhost:5000)**

Upload an APK and get an instant security analysis.

---

# 🧠 **How Detection Works**

### **Feature Extraction**

* Certificate info
* Requested permissions
* Package metadata
* APK manifest patterns
* Structural anomalies

### **ML Pipelines**

* Certificate model
* Permission classifier
* Package behavior model
* Ensemble logic

Each model outputs probabilities → combined into a **final risk score (0–100)**.

---

# 📊 Screenshot Preview

![Landing](https://github.com/user-attachments/assets/a42c3d34-ebf3-43bb-85ca-b1534f4cd69e)
![Dashboard](https://github.com/user-attachments/assets/cc346157-b832-4fd3-946c-26d7436af6e8)
![Report](https://github.com/user-attachments/assets/a99edd0a-6798-4a9e-b644-fd5024d2f23a)

---

# 🌐 **API Endpoints**

| Method | Route          | Description               |
| ------ | -------------- | ------------------------- |
| `POST` | `/analyze`     | Upload an APK and analyze |
| `GET`  | `/history`     | Previous scan results     |
| `GET`  | `/report/<id>` | Detailed risk report      |

---

# 📦 **Database Structure (SQLite)**

Stores:

* APK filename
* Extracted features
* ML predictions
* Risk score
* Timestamp

---

# 🤝 Contributing

Contributions welcome!

```bash
git checkout -b feature/my-feature
git commit -m "Add feature"
git push origin feature/my-feature
```

Then open a PR.

---

# 📜 License

This project is under the **MIT License**.

