import json
import os
import re
import math
import joblib
import datetime
from collections import Counter
import hashlib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction import DictVectorizer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb

# Utilities
def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())

def to_timestamp(date_str: str) -> float:
    if not date_str:
        return 0.0
    try:
        ds = str(date_str).replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(ds).timestamp()
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(str(date_str), fmt).timestamp()
            except Exception:
                continue
    return 0.0

def row_hash(row):
    return hashlib.sha256(str(row.values).encode()).hexdigest()

def proportion_and_overlap(train_df, test_df):
    print("Proportion_train")
    print(train_df["label"].value_counts(normalize=True))
    print("Proportion_test")
    print(test_df["label"].value_counts(normalize=True))

    train_hashes = set(train_df.apply(row_hash, axis=1))
    test_hashes = set(test_df.apply(row_hash, axis=1))

    print("Overlap:", len(train_hashes & test_hashes))

def encode_permissions_full(permissions, encoder, max_perms=12):
    """One-hot encode permissions and add normalized count"""
    X = np.zeros((1, len(encoder.classes_) + 1))
    for i, perm in enumerate(encoder.classes_):
        if perm in permissions:
            X[0, i] = 1
    X[0, -1] = min(len(permissions), max_perms) / max_perms
    return X



# Custom transformer functions
def extract_package_text(X):
    """Extract text features from DataFrame"""
    if isinstance(X, pd.DataFrame):
        return (X['package_name'].fillna('') + ' ' + 
                X['app_name'].fillna('') + ' ' + 
                X['app_version'].fillna('')).values
    return X

def extract_package_numeric(X):
    """Extract numeric features from DataFrame"""
    if isinstance(X, pd.DataFrame):
        features = []
        for _, row in X.iterrows():
            feat = PackageNameDetector.extract_numeric_features(
                package_name=row.get("package_name", ""),
                app_name=row.get("app_name", ""),
                # app_version=row.get("app_version", ""),
                min_sdk=row.get("min_sdk", 0),
                target_sdk=row.get("target_sdk", 0),
                app_size_mb=row.get("app_size_mb", 0.0)
            )
            features.append(feat)
        return features
    return X

def extract_certificate_features(X):
    """Extract certificate features from DataFrame"""
    if isinstance(X, pd.DataFrame):
        features = []
        for _, row in X.iterrows():
            cert = {
                "subject": row.get("subject", ""),
                "issuer": row.get("issuer", ""),
                "not_before": row.get("not_before", ""),
                "not_after": row.get("not_after", ""),
                # "public_key_algorithm": row.get("public_key_algorithm", ""),
                # "signature_algorithm": row.get("signature_algorithm", ""),
                # "key_size": row.get("key_size", 0),
                # "chain_length": row.get("chain_length", 1),
                "subject_common_name": row.get("subject_common_name", ""),
            }
            features.append(CertificateDetector.extract_core_features(cert))
        return features
    return X


# Package Name Detector (Core)
class PackageNameDetector:
    """
    Minimal core feature model for package/app authenticity.
    Text: TF-IDF(char n-grams) over "package_name app_name app_version"
    Numeric: pkg_length, pkg_depth, pkg_entropy, has_com_domain, has_org_domain, has_known_domain,
             min_sdk, target_sdk, sdk_gap, app_size_mb, tiny_app
    """

    def __init__(self,
                 model_path="models/package_model.pkl",
                 vectorizer_path="models/package_vectorizer.pkl",
                 scaler_path="models/package_scaler.pkl",
                 dictvec_path="models/package_dictvec.pkl"):
        if not all(os.path.exists(p) for p in [model_path, vectorizer_path, scaler_path, dictvec_path]):
            raise FileNotFoundError("Model/vectorizers not found. Train the package model first.")
        self.model = joblib.load(model_path)
        self.text_vectorizer = joblib.load(vectorizer_path)
        self.scaler = joblib.load(scaler_path)
        self.dict_vectorizer = joblib.load(dictvec_path)

    @staticmethod
    def extract_numeric_features(package_name: str,
                                 app_name: str,
                                #  app_version: str,
                                 min_sdk: int = 0,
                                 target_sdk: int = 0,
                                 app_size_mb: float = 0.0) -> dict:
        pn = package_name or ""
        return {
            "pkg_length": len(pn),
            "pkg_depth": pn.count('.'),
            "pkg_entropy": calculate_entropy(pn),
            "has_com_domain": 1 if pn.startswith("com.") else 0,
            "has_org_domain": 1 if pn.startswith("org.") else 0,
            # "has_known_domain": 1 if any(pn.startswith(d) for d in PackageNameDetector.KNOWN_DOMAINS) else 0,
            "min_sdk": int(min_sdk or 0),
            "target_sdk": int(target_sdk or 0),
            "sdk_gap": max(0, int(target_sdk or 0) - int(min_sdk or 0)),
            "app_size_mb": float(app_size_mb or 0.0),
            "tiny_app": 1 if 0 < float(app_size_mb or 0.0) < 1.0 else 0,
        }

    def _make_text(self, package_name: str, app_name: str) -> str:
        return f"{package_name or ''} {app_name or ''}".strip()

    def _vectorize(self, text: str, features: dict):
        X_text = self.text_vectorizer.transform([text])
        X_num = self.dict_vectorizer.transform([features])
        X_num = self.scaler.transform(X_num.toarray())
        return np.hstack([X_text.toarray(), X_num])

    def predict(self, package_name: str, app_name: str,
                min_sdk: int = 0, target_sdk: int = 0, app_size_mb: float = 0.0) -> bool:
        if not package_name or not app_name:
            return False
        feats = self.extract_numeric_features(package_name, app_name, min_sdk, target_sdk, app_size_mb)
        text = self._make_text(package_name, app_name)
        X = self._vectorize(text, feats)
        pred = self.model.predict(X)[0]
        return bool(pred)

    def predict_proba(self, package_name: str, app_name: str,
                      min_sdk: int = 0, target_sdk: int = 0, app_size_mb: float = 0.0) -> float:
        if not package_name or not app_name:
            return 0.0
        feats = self.extract_numeric_features(package_name, app_name, min_sdk, target_sdk, app_size_mb)
        text = self._make_text(package_name, app_name)
        X = self._vectorize(text, feats)
        proba = self.model.predict_proba(X)[0]
        return float(proba[1] if len(proba) > 1 else proba)

def train_package_model(train_csv_path="../ml_data/packages_train.csv",
                        test_csv_path="../ml_data/packages_test.csv",
                        model_dir="models"):
    if not os.path.exists(train_csv_path) or not os.path.exists(test_csv_path):
        raise FileNotFoundError(f"Missing train/test: {train_csv_path}, {test_csv_path}")

    os.makedirs(model_dir, exist_ok=True)

    train_df = pd.read_csv(train_csv_path)
    test_df = pd.read_csv(test_csv_path)

    required_cols = ["package_name", "app_name", "min_sdk", "target_sdk", "app_size_mb", "label"]
    for df in (train_df, test_df):
        missing = [c for c in required_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns: {missing}")

    for df in (train_df, test_df):
        df["package_name"] = df["package_name"].astype(str).fillna("")
        df["app_name"] = df["app_name"].astype(str).fillna("")
        # df["app_version"] = df["app_version"].astype(str).fillna("")
        for c in ["min_sdk", "target_sdk", "app_size_mb"]:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
        df["label"] = df["label"].map({"benign": 0, "malicious": 1, 0: 0, 1: 1}).fillna(0).astype(int)

    # Text features
    train_text = (train_df['package_name'] + ' ' + train_df['app_name']).values
    test_text = (test_df['package_name'] + ' ' + test_df['app_name']).values

    text_vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 6), max_features=3000, min_df=2, max_df=0.95)
    X_train_text = text_vectorizer.fit_transform(train_text)
    X_test_text = text_vectorizer.transform(test_text)

    # Numeric features
    def row_feats(row):
        return PackageNameDetector.extract_numeric_features(
            package_name=row["package_name"],
            app_name=row["app_name"],
            # app_version=row["app_version"],
            min_sdk=row["min_sdk"],
            target_sdk=row["target_sdk"],
            app_size_mb=row["app_size_mb"]
        )

    train_feats = train_df.apply(row_feats, axis=1).tolist()
    test_feats = test_df.apply(row_feats, axis=1).tolist()

    dict_vectorizer = DictVectorizer(sparse=True)
    X_train_num = dict_vectorizer.fit_transform(train_feats)
    X_test_num = dict_vectorizer.transform(test_feats)

    scaler = StandardScaler(with_mean=False)
    X_train_num_scaled = scaler.fit_transform(X_train_num)
    X_test_num_scaled = scaler.transform(X_test_num)

    X_train = np.hstack([X_train_text.toarray(), X_train_num_scaled.toarray()])
    X_test = np.hstack([X_test_text.toarray(), X_test_num_scaled.toarray()])

    y_train = train_df["label"].values
    y_test = test_df["label"].values

    model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        subsample=0.4,
        colsample_bytree=0.5,
        random_state=42,
        eval_metric='logloss',
        base_score=0.5
    )

    print("Training package model (core features)...")
    model.fit(X_train, y_train)


    proportion_and_overlap(train_df, test_df)
    print(f"Training Accuracy: {accuracy_score(y_train, model.predict(X_train)):.4f}")
    print(f"Testing Accuracy: {accuracy_score(y_test, model.predict(X_test)):.4f}")
    print("\nTest Set Classification Report:")
    print(classification_report(y_test, model.predict(X_test)))

    joblib.dump(model, os.path.join(model_dir, "package_model.pkl"))
    joblib.dump(text_vectorizer, os.path.join(model_dir, "package_vectorizer.pkl"))
    joblib.dump(scaler, os.path.join(model_dir, "package_scaler.pkl"))
    joblib.dump(dict_vectorizer, os.path.join(model_dir, "package_dictvec.pkl"))

    print(f"✅ Package model (core) saved to {model_dir}/")

    return model, text_vectorizer, scaler, dict_vectorizer


# Certificate Detector (Core)
class CertificateDetector:
    """
    Minimal core feature model for certificate authenticity.
    """

    def __init__(self,
                 model_path="models/certificate_model.pkl",
                 vectorizer_path="models/certificate_vectorizer.pkl"):
        if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
            raise FileNotFoundError("Model/vectorizer not found. Train the certificate model first.")
        self.model = joblib.load(model_path)
        self.dict_vectorizer = joblib.load(vectorizer_path)

    @staticmethod
    def extract_core_features(certificate: dict) -> dict:
        cert = certificate or {}

        issuer = str(cert.get("issuer", "") or "")
        subject = str(cert.get("subject", "") or "")
        subject_cn = str(cert.get("subject_common_name", "") or "")

        if not subject_cn and subject:
            m = re.search(r"CN\s*=\s*([^,]+)", subject)
            if m:
                subject_cn = m.group(1).strip()

        try:
            key_size = int(cert.get("key_size", 0) or 0)
        except Exception:
            key_size = 0

        not_before = to_timestamp(cert.get("not_before", ""))
        not_after = to_timestamp(cert.get("not_after", ""))
        validity_days = 0.0
        if not_before > 0 and not_after > 0 and not_after > not_before:
            validity_days = (not_after - not_before) / (24 * 3600)

        now_ts = datetime.datetime.now().timestamp()
        is_expired = 1 if (not_after > 0 and not_after < now_ts) else 0
        is_not_yet_valid = 1 if (not_before > now_ts) else 0

        is_self_signed = 1 if (subject and issuer and subject == issuer) else 0

        cn = subject_cn.strip()
        cn_has_wildcard = 1 if cn.startswith("*.") else 0
        cn_is_ip = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', cn or "") else 0

        return {
            # "is_self_signed": is_self_signed,
            "cn_has_wildcard": cn_has_wildcard,
            "cn_is_ip": cn_is_ip,
            "key_size": key_size,
            "validity_days": float(validity_days),
            "is_expired": is_expired,
            "is_not_yet_valid": is_not_yet_valid,
        }

    def _vectorize(self, features: dict):
        return self.dict_vectorizer.transform([features])

    def predict(self, certificate: dict) -> bool:
        if not certificate or not isinstance(certificate, dict):
            return False
        feats = self.extract_core_features(certificate)
        X = self._vectorize(feats)
        pred = self.model.predict(X)[0]
        return bool(pred)

    def predict_proba(self, certificate: dict) -> float:
        if not certificate or not isinstance(certificate, dict):
            return 0.0
        feats = self.extract_core_features(certificate)
        X = self._vectorize(feats)
        proba = self.model.predict_proba(X)[0]
        return float(proba[1] if len(proba) > 1 else proba)

def train_certificate_model(train_csv_path="../ml_data/certificates_train.csv",
                            test_csv_path="../ml_data/certificates_test.csv",
                            model_dir="models"):
    if not os.path.exists(train_csv_path) or not os.path.exists(test_csv_path):
        raise FileNotFoundError(f"Missing train/test: {train_csv_path}, {test_csv_path}")

    os.makedirs(model_dir, exist_ok=True)

    train_df = pd.read_csv(train_csv_path)
    test_df = pd.read_csv(test_csv_path)

    if "package_name" in train_df.columns:
        train_df = train_df.drop(columns=["package_name"])
    if "package_name" in test_df.columns:
        test_df = test_df.drop(columns=["package_name"])


    for df in (train_df, test_df):
        df["label"] = df["label"].map({"benign": 0, "malicious": 1, 0: 0, 1: 1}).fillna(0).astype(int)

    def row_feats(row):
        cert = {
            "subject": row.get("subject", ""),
            "issuer": row.get("issuer", ""),
            "not_before": row.get("not_before", ""),
            "not_after": row.get("not_after", ""),
            "key_size": row.get("key_size", 0),
            "subject_common_name": row.get("subject_common_name", ""),
        }
        for k in ("key_size"):
            try:
                cert[k] = int(cert.get(k, 0) or 0)
            except Exception:
                cert[k] = 0
        return CertificateDetector.extract_core_features(cert)

    X_train_dicts = train_df.apply(row_feats, axis=1).tolist()
    X_test_dicts = test_df.apply(row_feats, axis=1).tolist()
    y_train = train_df["label"].values
    y_test = test_df["label"].values

    dict_vectorizer = DictVectorizer(sparse=True)
    X_train = dict_vectorizer.fit_transform(X_train_dicts)
    X_test = dict_vectorizer.transform(X_test_dicts)

    model = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric='logloss',
        base_score=0.5
    )

    print("Training certificate model (core features)...")
    model.fit(X_train, y_train)

    proportion_and_overlap(train_df, test_df)
    print(f"Training Accuracy: {accuracy_score(y_train, model.predict(X_train)):.4f}")
    print(f"Testing Accuracy: {accuracy_score(y_test, model.predict(X_test)):.4f}")
    print("\nTest Set Classification Report:")
    print(classification_report(y_test, model.predict(X_test)))

    joblib.dump(model, os.path.join(model_dir, "certificate_model.pkl"))
    joblib.dump(dict_vectorizer, os.path.join(model_dir, "certificate_vectorizer.pkl"))

    print(f"✅ Certificate model (core) saved to {model_dir}/")

    return model, dict_vectorizer


# Permission Pattern Detector (Core)
class PermissionPatternDetector:
    """
    Core model: One-hot encoding over permissions, Logistic Regression with class_weight='balanced'.
    """

    def __init__(self, model_path="models/permission_model.pkl", encoder_path="models/permission_encoder.pkl"):
        if not os.path.exists(model_path) or not os.path.exists(encoder_path):
            raise FileNotFoundError("Model/encoder not found. Train the permission model first.")
        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)

    def predict(self, permissions: list[str]) -> bool:
        if not permissions or not isinstance(permissions, (list, tuple)):
            return False
        X = encode_permissions_full(permissions, self.encoder)
        return bool(self.model.predict(X)[0])

    def predict_proba(self, permissions: list[str]) -> float:
        if not permissions or not isinstance(permissions, (list, tuple)):
            return 0.0
        X = encode_permissions_full(permissions, self.encoder)
        proba = self.model.predict_proba(X)[0]
        return float(proba[1] if len(proba) > 1 else proba)

def train_permission_model(
    train_csv_path="../ml_data/permissions_train.csv",
    test_csv_path="../ml_data/permissions_test.csv",
    model_dir="models",
    max_perms=12,
    min_perm_count=5  # Remove permissions appearing less than this
):
    if not os.path.exists(train_csv_path) or not os.path.exists(test_csv_path):
        raise FileNotFoundError(f"Missing train/test: {train_csv_path}, {test_csv_path}")

    os.makedirs(model_dir, exist_ok=True)

    # Load
    train_df = pd.read_csv(train_csv_path).dropna(subset=["permissions", "label"])
    test_df = pd.read_csv(test_csv_path).dropna(subset=["permissions", "label"])

    # Normalize labels
    label_map = {0: 0, 1: 1, "benign": 0, "malicious": 1}
    train_df["label"] = train_df["label"].map(label_map).astype(int)
    test_df["label"] = test_df["label"].map(label_map).astype(int)

    # Convert permissions to lists
    def process_perms(x):
        perms = [p.strip() for p in str(x).split(",") if p.strip()]
        return perms[:max_perms]

    X_train_raw = train_df["permissions"].apply(process_perms).tolist()
    X_test_raw = test_df["permissions"].apply(process_perms).tolist()

    # Count permissions in training
    perm_counts = Counter(p for perms in X_train_raw for p in perms)
    allowed_perms = {p for p, c in perm_counts.items() if c >= min_perm_count}

    # Filter rare permissions
    def filter_rare(perms):
        return [p for p in perms if p in allowed_perms]

    X_train_filtered = [filter_rare(perms) for perms in X_train_raw]
    X_test_filtered = [filter_rare(perms) for perms in X_test_raw]

    # One-hot encode
    encoder = MultiLabelBinarizer(sparse_output=False)
    X_train_onehot = encoder.fit_transform(X_train_filtered)
    X_test_onehot = encoder.transform(X_test_filtered)

    # Add normalized permission count
    train_perm_count = np.array([len(p) for p in X_train_filtered]).reshape(-1, 1) / max_perms
    test_perm_count = np.array([len(p) for p in X_test_filtered]).reshape(-1, 1) / max_perms

    X_train = np.hstack([X_train_onehot, train_perm_count])
    X_test = np.hstack([X_test_onehot, test_perm_count])

    y_train = train_df["label"].values
    y_test = test_df["label"].values

    # Train Logistic Regression
    model = LogisticRegression(max_iter=2000, class_weight="balanced", solver="lbfgs", random_state=42)
    model.fit(X_train, y_train)

    proportion_and_overlap(train_df, test_df)
    print("Training Accuracy:", accuracy_score(y_train, model.predict(X_train)))
    print("Testing Accuracy:", accuracy_score(y_test, model.predict(X_test)))
    print("\nClassification Report:")
    print(classification_report(y_test, model.predict(X_test)))

    # Save model and encoder
    joblib.dump(model, os.path.join(model_dir, "permission_model.pkl"))
    joblib.dump(encoder, os.path.join(model_dir, "permission_encoder.pkl"))

    print(f"✅ Filtered permission model saved to {model_dir}/")

    return model, encoder


# Pipeline Orchestrator
def get_available_datasets(base_path="../ml_data"):
    if not os.path.exists(base_path):
        return []
    files = set(os.listdir(base_path))
    datasets = []
    for f in files:
        if f.endswith("_train.csv"):
            name = f[:-10]  # strip _train.csv
            if f"{name}_test.csv" in files:
                datasets.append(name)
    return datasets


def main():
    print("Core APK Analysis ML Training Pipeline")
    print("=" * 50)

    base_path = "../ml_data"
    available = get_available_datasets(base_path)
    print(f"Available datasets: {available}")

    # Train package model (if available)
    if "packages" in available:
        print("\n1) Training PackageNameDetector (core)...")
        try:
            train_package_model(
                train_csv_path=f"{base_path}/packages_train.csv",
                test_csv_path=f"{base_path}/packages_test.csv",
                model_dir="models"
            )
        except Exception as e:
            print(f"Failed to train package model: {e}")
    else:
        print("⚠️  packages dataset not found")

    # Train permission model (if available)
    if "permissions" in available:
        print("\n2) Training PermissionPatternDetector (core)...")
        try:
            train_permission_model(
                train_csv_path=f"{base_path}/permissions_train.csv",
                test_csv_path=f"{base_path}/permissions_test.csv",
                model_dir="models"
            )
        except Exception as e:
            print(f"Failed to train permission model: {e}")
    else:
        print("⚠️  permissions dataset not found")

    # Train certificate model (if available)
    if "certificates" in available:
        print("\n3) Training CertificateDetector (core)...")
        try:
            train_certificate_model(
                train_csv_path=f"{base_path}/certificates_train.csv",
                test_csv_path=f"{base_path}/certificates_test.csv",
                model_dir="models"
            )
        except Exception as e:
            print(f"Failed to train certificate model: {e}")
    else:
        print("⚠️  certificates dataset not found")



    print("\n🏁 Core training pipeline completed!")


if __name__ == "__main__":
    main()