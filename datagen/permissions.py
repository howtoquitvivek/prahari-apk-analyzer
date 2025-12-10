import csv
import random
from pathlib import Path

# -------------------------------
# Configuration (Fully Configurable)
# -------------------------------
TRAIN_SAMPLES = 50000
TEST_SAMPLES = 5000

BENIGN_RATIO = 0.689  # benign/malicious ratio

# Permission count ranges
PERM_RANGE_BANKING = (25, 55)   # Legit banking apps
PERM_RANGE_BENIGN = (4, 15)     # Other benign apps
PERM_RANGE_DROPPER = (2, 20)    # Malicious apps (droppers)

MAX_PERMISSIONS_PER_APP = 60  # hard cap (for safety)

# Probabilities
P_BANKING_PATTERN = 0.2   # % chance benign app is banking-style
P_BENIGN_HAS_RISKY = 0.1  # % chance benign app includes risky perms
P_SUPER_PERM_MAL = 0.1    # % chance malware has extra permissions

# -------------------------------
# Permission Pools
# -------------------------------
common_benign_perms = ['android.permission.MICROPHONE','com.fss.indus.permission.C2D_MESSAGE', 'net.one97.paytm.COMMON_BROADCAST_PERMISSION', 'android.permission.WRITE_CALENDAR', 'com.bankofbaroda.mconnect.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.CAMERA', 'android.permission.CHANGE_WIFI_MULTICAST_STATE', 'com.huawei.appmarket.service.commondata.permission.GET_COMMON_DATA', 'android.permission.READ_PHONE_NUMBERS', 'android.permission.REORDER_TASKS', 'android.permission.CHANGE_WIFI_STATE', 'android.permission.HIDE_OVERLAY_WINDOWS', 'android.permission.BLUETOOTH_ADMIN', 'me.everything.badger.permission.BADGE_COUNT_WRITE', 'com.samsung.android.providers.context.permission.WRITE_USE_APP_FEATURE_SURVEY', 'android.permission.READ_INTERNAL_STORAGE', 'com.oppo.launcher.permission.READ_SETTINGS', 'android.Manifest.permission.READ_PHONE_STATE', 'com.sec.android.provider.badge.permission.WRITE', 'com.htc.launcher.permission.UPDATE_SHORTCUT', 'android.permission.AUTHENTICATE_ACCOUNTS', 'com.oppo.launcher.permission.WRITE_SETTINGS', 'android.permission.READ_CONTACTS', 'android.permission.CHANGE_NETWORK_STATE', 'android.permission.HIGH_SAMPLING_RATE_SENSORS', 'android.permission.USE_CREDENTIALS', 'com.google.android.gms.permission.AD_ID', 'com.android.launcher.permission.INSTALL_SHORTCUT', 'android.permission.ACCESS_WIFI_STATE', 'android.Manifest.permission.ACCESS_FINE_LOCATION', 'android.permission.VIBRATE', 'com.fss.indus.permission.MAPS_RECEIVE', 'com.google.android.providers.gsf.permission.READ_GSERVICES', 'com.sbi.lotusintouch.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.FLASHLIGHT', 'android.permission.FOREGROUND_SERVICE_DATA_SYNC', 'android.permission.ACCESS_MEDIA_LOCATION', 'android.permission.NFC', 'android.permission.ACCESS_ADSERVICES_AD_ID', 'android.permission.DETECT_SCREEN_RECORDING', 'me.everything.badger.permission.BADGE_COUNT_READ', 'net.one97.paytm.COMMON_NATIVE_BROADCAST_PERMISSION', 'android.permission.GET_ACCOUNTS', 'android.permission.READ_MEDIA_AUDIO', 'android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION', 'android.permission.WAKE_LOCK', 'android.permission.FOREGROUND_SERVICE', 'com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE', 'android.permission.READ_PRIVILEGED_PHONE_STATE', 'com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge.deveventspermission', 'android.permission.BROADCAST_CLOSE_SYSTEM_DIALOGS', 'android.webkit.resource.AUDIO_CAPTURE', 'android.permission.FOREGROUND_SERVICE_SPECIAL_USE', 'android.permission.READ_PHONE_STATEandroid.permission.WAKE_LOCK', 'com.csam.icici.bank.imobile.permission.C2D_MESSAGE', 'android.permission.SYSTEM_ALERT_WINDOW', 'com.huawei.android.launcher.permission.WRITE_SETTINGS', 'android.permission.ACCESS_FINE_LOCATION', 'net.one97.paytm.permission.LAYER_PUSH', 'android.permission.READ_APP_BADGE', 'android.permission.USE_FULL_SCREEN_INTENT', 'com.anddoes.launcher.permission.UPDATE_COUNT', 'android.permission.USE_FINGERPRINT', 'android.permission.POST_NOTIFICATIONS', 'com.majeur.launcher.permission.UPDATE_BADGE', 'com.samsung.android.mapsagent.permission.READ_APP_INFO', 'com.phonepe.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.SCHEDULE_EXACT_ALARM', 'com.google.android.c2dm.permission.RECEIVE', 'com.axis.mobile.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'com.huawei.android.launcher.permission.READ_SETTINGS', 'com.phonepe.app.permission.C2D_MESSAGE', 'com.fedmobile.permission.RSYS_SHOW_IAM', 'android.permission.WRITE_INTERNAL_STORAGE', 'android.permission.USER_STATE', 'android.permission.SEND_SMS', 'com.sec.android.provider.badge.permission.READ', 'android.permission.REQUEST_DELETE_PACKAGES', 'com.fedmobile.permission.PUSHIO_MESSAGE', 'android.permission.ACCESS_ADSERVICES_ATTRIBUTION', 'com.huawei.android.launcher.permission.CHANGE_BADGE', 'android.permission.ACCESS_LOCATION', 'net.one97.paytm.upi.provider.permission.WRITE_MODES', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.ACCESS_COARSE_LOCATION', 'net.one97.paytm.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.ACCESS_DOWNLOAD_MANAGER', 'com.phonepe.app.permission.SYNC_COMPLETE', 'android.permission.RECORD_AUDIO', 'android.permission.DETECT_SCREEN_CAPTURE', 'android.permission.ACCESS_NOTIFICATION_POLICY', 'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS', 'android.permission.WRITE_SYNC_SETTINGS', 'net.one97.paytm.permission.UA_DATA', 'net.one97.paytm.permission.C2D_MESSAGE', 'android.permission.BLUETOOTH_CONNECT', 'com.csam.icici.bank.imobile.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'in.org.npci.upiapp.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'com.htc.launcher.permission.READ_SETTINGS', 'android.permission.CALL_PHONE', 'com.android.launcher.permission.UNINSTALL_SHORTCUT', 'com.fedmobile.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'com.android.vending.CHECK_LICENSE', 'android.permission.QUERY_ALL_PACKAGES', 'android.permission.MODIFY_AUDIO_SETTINGS', 'android.webkit.resource.VIDEO_CAPTURE', 'android.permission.BLUETOOTH', 'android.permission.ACCESS_NETWORK_STATE', 'com.huawei.android.launcher.permission.READ_SETTINGScom.oppo.launcher.permission.WRITE_SETTINGS', 'android.permission.BIND_APPWIDGET', 'android.permission.READ_PHONE_STATE', 'com.fedmobile.permission.C2D_MESSAGE', 'com.google.android.c2dm.permission.SEND', 'com.sonyericsson.home.permission.BROADCAST_BADGE', 'android.permission.ACCESS_COARSE_UPDATES', 'android.permission.USE_BIOMETRIC', 'android.permission.READ_MEDIA_VISUAL_USER_SELECTED', 'android.permission.FOREGROUND_SERVICE_MICROPHONE', 'android.permission.READ_MEDIA_IMAGES', 'android.permission.READ_PROFILE', 'com.sonymobile.home.permission.PROVIDER_INSERT_BADGE', 'net.one97.paytm.upi.provider.permission.READ_MODES', 'android.permission.READ_SYNC_SETTINGS', 'android.hardware.camera.autofocus', 'com.snapwork.hdfc.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.INTERNET', 'android.permission.READ_BASIC_PHONE_STATE', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.READ_CALENDAR', 'android.permission.READ_EXTERNAL_STORAGE', 'com.axis.mobile.permission.C2D_MESSAGE', 'android.permission.DOWNLOAD_WITHOUT_NOTIFICATION', 'android.permission.GET_TASKS','com.sbi.SBIFreedomPlus.permission.C2D_MESSAGE']

risky_perms = ['android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.INSTALL_SELF_UPDATESandroid.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.ACCESS_NETWORK_STATE', 'android.permission.WRITE_EXTERNAL_STORAGE', 'com.jynns.android.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.RECORD_AUDIO', 'android.permission.WRITE_CONTACTS', 'com.NWilfxj.FxKDr.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.USE_BIOMETRIC', 'android.permission.QUERY_ALL_PACKAGES', 'com.google.android.c2dm.permission.RECEIVE', 'android.permission.CAMERA', 'android.permission.ACCESS_ADSERVICES_AD_ID', 'android.permission.FOREGROUND_SERVICE', 'android.permission.READ_CONTACTS', 'android.permission.RECEIVE_SMS', 'android.permission.INSTALL_PACKAGE_UPDATES', 'com.example.example.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.READ_INSTALL_SESSIONS', 'android.permission.READ_SMS', 'android.permission.ACCESS_WIFI_STATE', 'android.permission.REQUEST_DELETE_PACKAGES', 'android.permission.READ_PHONE_STATE', 'android.permission.POST_NOTIFICATIONS', 'android.permission.QUERY_ALL_PACKAGESandroid.permission.QUERY_ALL_PACKAGES', 'android.permission.WAKE_LOCK', 'android.permission.INTERNET', 'android.permission.READ_PHONE_NUMBERS', 'com.uvsjtq.ubxzjtjugbt.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.DELETE_PACKAGES', 'android.permission.INTERNETandroid.permission.INSTALL_PACKAGES', 'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS', 'android.permission.SEND_SMS', 'com.android.permission.INSTALL_EXISTING_PACKAGES']

# Unique banking app patterns (some risky perms are legit here)
banking_patterns = [
    [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.USE_BIOMETRIC",
    ],
    [
        "android.permission.INTERNET",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.READ_CONTACTS",
    ],
]

# -------------------------------
# Helper Functions
# -------------------------------
def safe_sample(pool, k):
    return random.sample(pool, k=min(len(pool), k))

def generate_permissions(label: str):
    perms = []

    if label == "benign":
        if random.random() < P_BANKING_PATTERN:
            # Banking-style benign app
            base = random.choice(banking_patterns)
            extra = safe_sample(
                common_benign_perms + risky_perms,
                random.randint(PERM_RANGE_BANKING[0], PERM_RANGE_BANKING[1]) - len(base)
            )
            perms = list(set(base + extra))
        else:
            # Normal benign app
            perms = safe_sample(common_benign_perms, random.randint(*PERM_RANGE_BENIGN))
            if random.random() < P_BENIGN_HAS_RISKY:
                perms += safe_sample(risky_perms, random.randint(1, 3))

    else:  # malicious (droppers)
        perms = safe_sample(common_benign_perms, random.randint(0, 5))
        perms += safe_sample(risky_perms, random.randint(1, 5))

        # Restrict to dropper range
        target_size = random.randint(*PERM_RANGE_DROPPER)
        perms = perms[:target_size]

        if random.random() < P_SUPER_PERM_MAL:
            perms += safe_sample(common_benign_perms + risky_perms, random.randint(2, 5))

    return list(set(perms))[:MAX_PERMISSIONS_PER_APP]

def generate_dataset(n_samples: int, benign_ratio: float):
    n_benign = int(n_samples * benign_ratio)
    n_malicious = n_samples - n_benign
    dataset = []

    for _ in range(n_benign):
        dataset.append({"permissions": ",".join(generate_permissions("benign")), "label": "benign"})
    for _ in range(n_malicious):
        dataset.append({"permissions": ",".join(generate_permissions("malicious")), "label": "malicious"})

    random.shuffle(dataset)
    return dataset

def save_csv(dataset, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["permissions", "label"])
        writer.writeheader()
        for row in dataset:
            writer.writerow(row)

# -------------------------------
# Generate and Save
# -------------------------------
train_data = generate_dataset(TRAIN_SAMPLES, BENIGN_RATIO)
test_data = generate_dataset(TEST_SAMPLES, BENIGN_RATIO)

save_csv(train_data, "output/permissions_train.csv")
save_csv(test_data, "output/permissions_test.csv")

print("✅ Dataset generated successfully:")
print(f"  Train: {TRAIN_SAMPLES} samples -> permissions_train.csv")
print(f"  Test:  {TEST_SAMPLES} samples -> permissions_test.csv")