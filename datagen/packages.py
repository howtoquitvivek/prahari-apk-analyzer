import csv
import random
import statistics
from pathlib import Path

# -------------------------------
# Configuration
# -------------------------------
TRAIN_SAMPLES = 50000
TEST_SAMPLES = 5000
BENIGN_RATIO = 0.733

# SDK + size ranges
BENIGN_MIN_SDK_RANGE = (19, 31)
BENIGN_TARGET_SDK_RANGE = (28, 36)
BENIGN_APP_SIZE_MB_RANGE = (35, 250)

MAL_MIN_SDK_RANGE = (15, 25)
MAL_TARGET_SDK_RANGE = (22, 36)
MAL_APP_SIZE_MB_RANGE = (0.5, 50)

# -------------------------------
# Real Pools (fill with your own data)
# -------------------------------
benign_packages = [
    'com.snapwork.IDBI', 'com.hdfcbank.android.now', 'com.axis.mobile', 'com.fedmobile', 'com.sbi.SBIFreedomPlus', 'com.fss.indus', 'com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge', 'in.org.npci.upiapp', 'com.bankofbaroda.mconnect', 'com.snapwork.hdfc', 'com.csam.icici.bank.imobile', 'net.one97.paytm', 'com.phonepe.app', 'com.sbi.lotusintouch'
]
benign_appnames = [
    'PhonePe', 'HDFC Bank App', 'IndusMobile', 'BHIM', 'bob World', 'Paytm', 'YONO SBI', 'HDFC Bank', 'Axis Mobile', 'Yono Lite SBI', 'iMobile', 'IDBI Bank', 'FedMobile', 'Kotak811'
]

malicious_packages = [
    'com.uvsjtq.ubxzjtjugbt', 'com.rc888.baxi.English', 'com.skyspot.Trading', 'com.jynns.android', 'com.lgcylq.jkohjvyijw', 'com.tus.efdfbbp', 'com.example.example', 'com.mbxajzg.nwacm', 'com.hFEOw.NkTdhVmwB', 'com.saltedge.fake_oauth_client_xf', 'com.nwpnit.znqxc', 'com.NWilfxj.FxKDr'
]
malicious_appnames = [
    "System Update", "Flash Player", "Free Gift Rewards",'Axis Bank', 'RBL Credit Card', 'ІΝDUЅІΝD Crеԁіt Cаrԁ', 'Sbi Cards Services', 'Ѕbі Crеԁіt Cаrԁ', 'Proteção Cartões', 'Му Cаrԁs', 'YONO SBI', 'Іոԁusіոԁ Crеԁіt Cаrԁ', 'AXIS Credit Card', 'mуCаrԁ', 'Fake Bank'
]

# -------------------------------
# Extractor
# -------------------------------
def analyze_packages(pool):
    prefixes, companies, domains, lengths = [], [], [], []
    for pkg in pool:
        parts = pkg.split(".")
        if len(parts) >= 3:
            prefixes.append(parts[0])
            companies.append(parts[1])
            domains.append(parts[2])
        elif len(parts) == 2:
            prefixes.append(parts[0])
            companies.append(parts[1])
        lengths.append(len(pkg))
    return {
        "prefixes": list(set(prefixes)),
        "companies": list(set(companies)),
        "domains": list(set(domains)),
        "avg_len": round(statistics.mean(lengths), 1) if lengths else 15,
    }

benign_stats = analyze_packages(benign_packages)
malicious_stats = analyze_packages(malicious_packages)

# -------------------------------
# Synthetic Generator
# -------------------------------
def generate_package_name(label: str):
    stats = benign_stats if label == "benign" else malicious_stats
    prefix = random.choice(stats["prefixes"]) if stats["prefixes"] else "com"
    company = random.choice(stats["companies"]) if stats["companies"] else "app"
    domain = random.choice(stats["domains"]) if stats["domains"] else "core"

    # Random chance to elongate/shorten to mimic avg_len
    base = f"{prefix}.{company}.{domain}"
    if random.random() < 0.3:  # add extra token
        base += "." + random.choice(["secure", "lite", "update", "pro", "service", "free"])
    return base

def generate_app_name(label: str):
    pool = benign_appnames if label == "benign" else malicious_appnames
    base = random.choice(pool)
    if random.random() < 0.4:  # synthetic variant
        suffix = random.choice(["Pro", "Lite", "2025", "Free", "Secure"])
        return f"{base} {suffix}"
    return base

def generate_sdk_and_size(label: str):
    if label == "benign":
        min_sdk = random.randint(*BENIGN_MIN_SDK_RANGE)
        target_sdk = random.randint(max(min_sdk, BENIGN_TARGET_SDK_RANGE[0]), BENIGN_TARGET_SDK_RANGE[1])
        app_size_mb = round(random.uniform(*BENIGN_APP_SIZE_MB_RANGE), 2)
    else:
        min_sdk = random.randint(*MAL_MIN_SDK_RANGE)
        target_sdk = random.randint(max(min_sdk, MAL_TARGET_SDK_RANGE[0]), MAL_TARGET_SDK_RANGE[1])
        app_size_mb = round(random.uniform(*MAL_APP_SIZE_MB_RANGE), 2)
    return min_sdk, target_sdk, app_size_mb

def generate_sample(label: str):
    pkg = generate_package_name(label)
    app = generate_app_name(label)
    min_sdk, target_sdk, app_size = generate_sdk_and_size(label)
    return {
        "package_name": pkg,
        "app_name": app,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "app_size_mb": app_size,
        "label": label,
    }

def generate_dataset(n_samples: int, benign_ratio: float):
    n_benign = int(n_samples * benign_ratio)
    n_mal = n_samples - n_benign
    dataset = [generate_sample("benign") for _ in range(n_benign)] + \
              [generate_sample("malicious") for _ in range(n_mal)]
    random.shuffle(dataset)
    return dataset

def save_csv(dataset, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["package_name", "app_name", "min_sdk", "target_sdk", "app_size_mb", "label"])
        writer.writeheader()
        writer.writerows(dataset)

# -------------------------------
# Generate
# -------------------------------
train_data = generate_dataset(TRAIN_SAMPLES, BENIGN_RATIO)
test_data = generate_dataset(TEST_SAMPLES, BENIGN_RATIO)

save_csv(train_data, "output/packages_train.csv")
save_csv(test_data, "output/packages_test.csv")

print("✅ Done: Generated train & test datasets")
