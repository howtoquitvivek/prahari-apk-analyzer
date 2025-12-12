import csv
import random
from pathlib import Path
from datetime import datetime, timedelta

# -------------------------------
# Configuration
# -------------------------------
TRAIN_SAMPLES = 50000
TEST_SAMPLES = 5000
BENIGN_RATIO = 0.675  # benign/malicious ratio

OUTPUT_DIR = Path("output")
# OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------------
# Real/Malicious Pools
# -------------------------------
real_subjects = ['Common Name: Android, Organizational Unit: Android, Organization: Google Inc., Locality: Mountain View, State/Province: California, Country: US', 'Common Name: Vivek Soneja, Organizational Unit: PhonePe, Organization: PhonePe, Locality: Bangalore, State/Province: Karnataka, Country: IN', 'Common Name: Bank of Baroda, Organizational Unit: Digital Banking, Organization: Bank of Baroda, Locality: Mumbai, State/Province: Maharashtra, Country: IN', 'Common Name: AXIS BANK, Organizational Unit: AXIS BANK, Organization: AXIS BANK, Locality: Mumbai, State/Province: Maharashtra, Country: 91', 'Organizational Unit: Federal Bank', 'Common Name: fssnet mpay, Organizational Unit: fss, Organization: fss, Locality: chennai, State/Province: tamilnadu, Country: 91', 'Common Name: BHIM, Organizational Unit: NPCI, Organization: NPCI, Locality: BANGALORE, State/Province: KARNATAKA, Country: IN', 'Common Name: Paytm, Organizational Unit: Engineering, Organization: Paytm, Locality: Noida, State/Province: Uttar Pradesh, Country: 91', 'Common Name: LOTUS, Organizational Unit: SBI GITC, Organization: SBI, Locality: NAVI MUMBAI, State/Province: MAHARASHTRA, Country: IN', 'Common Name: HDFC Bank, Organizational Unit: IT, Organization: Snapwork, Locality: Mumbai, State/Province: MH, Country: 91', 'Common Name: CodeSigning for STATE BANK OF INDIA, Organizational Unit: Android Code Signing, Organization: STATE BANK OF INDIA, Locality: Navi Mumbai, State/Province: Maharashtra, Country: IN', 'Common Name: ICICI BANK, Organizational Unit: ICICI BANK, Organization: ICICI BANK, Locality: MUMBAI, State/Province: MAHARASHTRA, Country: 91']

mal_subjects = ['Common Name: xolbzxs', 'Common Name: Dmitrii Barbasura, Organizational Unit: Salt Edge, Organization: Salt Edge Ltd, Locality: Ottawa, State/Province: Ontario, Country: CA', 'Common Name: bklcBIPVzk', 'Common Name: 的撒娇好, Organizational Unit: 的好姐姐, Organization: 点击, Locality: 大师级, State/Province: 黄金, Country: K:÷', 'Common Name: axis, Organizational Unit: axis, Organization: axis, Locality: ladakh, State/Province: leh, Country: india', 'Common Name: tQPtic', 'Common Name: sklndg, Organizational Unit: irugshel, Organization: dfuilgh, Locality: sdjkflcnjladsn, State/Province: oisdfhl, Country: 91', 'Common Name: Android, Organizational Unit: Android, Organization: Google, Locality: Mountain View, State/Province: California, Country: US', 'Common Name: uDxBFvtzt', 'Common Name: smgR', 'Common Name: ljRKCxEllEZC', 'Common Name: PLgkDbhpriL']

real_issuers = ['Common Name: LOTUS, Organizational Unit: SBI GITC, Organization: SBI, Locality: NAVI MUMBAI, State/Province: MAHARASHTRA, Country: IN', 'Common Name: Paytm, Organizational Unit: Engineering, Organization: Paytm, Locality: Noida, State/Province: Uttar Pradesh, Country: 91', 'Common Name: Android, Organizational Unit: Android, Organization: Google Inc., Locality: Mountain View, State/Province: California, Country: US', 'Common Name: AXIS BANK, Organizational Unit: AXIS BANK, Organization: AXIS BANK, Locality: Mumbai, State/Province: Maharashtra, Country: 91', 'Common Name: Vivek Soneja, Organizational Unit: PhonePe, Organization: PhonePe, Locality: Bangalore, State/Province: Karnataka, Country: IN', 'Common Name: HDFC Bank, Organizational Unit: IT, Organization: Snapwork, Locality: Mumbai, State/Province: MH, Country: 91', 'Common Name: Symantec CA for Android, Organizational Unit: Android Applications, Organization: Symantec Corporation, Country: US', 'Common Name: BHIM, Organizational Unit: NPCI, Organization: NPCI, Locality: BANGALORE, State/Province: KARNATAKA, Country: IN', 'Common Name: Bank of Baroda, Organizational Unit: Digital Banking, Organization: Bank of Baroda, Locality: Mumbai, State/Province: Maharashtra, Country: IN', 'Organizational Unit: Federal Bank', 'Common Name: fssnet mpay, Organizational Unit: fss, Organization: fss, Locality: chennai, State/Province: tamilnadu, Country: 91', 'Common Name: ICICI BANK, Organizational Unit: ICICI BANK, Organization: ICICI BANK, Locality: MUMBAI, State/Province: MAHARASHTRA, Country: 91']

mal_issuers = ['Common Name: uDxBFvtzt', 'Common Name: xolbzxs', 'Common Name: Android, Organizational Unit: Android, Organization: Google, Locality: Mountain View, State/Province: California, Country: US', 'Common Name: Dmitrii Barbasura, Organizational Unit: Salt Edge, Organization: Salt Edge Ltd, Locality: Ottawa, State/Province: Ontario, Country: CA', 'Common Name: sklndg, Organizational Unit: irugshel, Organization: dfuilgh, Locality: sdjkflcnjladsn, State/Province: oisdfhl, Country: 91', 'Common Name: PLgkDbhpriL', 'Common Name: ljRKCxEllEZC', 'Common Name: bklcBIPVzk', 'Common Name: tQPtic', 'Common Name: 的撒娇好, Organizational Unit: 的好姐姐, Organization: 点击, Locality: 大师级, State/Province: 黄金, Country: K:÷', 'Common Name: axis, Organizational Unit: axis, Organization: axis, Locality: ladakh, State/Province: leh, Country: india', 'Common Name: smgR']

# Pools of ISO dates
real_not_before_pool = ['2024-06-05T06:08:23+00:00', '2017-09-13T14:06:21+00:00', '2012-04-09T06:33:37+00:00', '2011-01-18T13:33:35+00:00', '2016-06-01T09:00:02+00:00', '2014-03-12T01:46:27+00:00', '2016-11-23T09:13:40+00:00', '2011-09-07T10:04:13+00:00', '2016-12-30T02:53:53+00:00', '2012-07-19T07:13:45+00:00', '2015-05-14T05:07:39+00:00', '2012-04-25T10:27:26+00:00', '2023-04-24T22:38:44+00:00', '2017-09-07T11:25:17+00:00']

real_not_after_pool = ['2054-06-05T06:08:23+00:00', '2053-04-24T22:38:44+00:00', '2039-01-23T10:04:13+00:00', '2041-11-17T09:13:40+00:00', '2047-09-07T11:25:17+00:00', '2067-09-01T14:06:21+00:00', '2062-04-13T10:27:26+00:00', '2039-03-07T20:24:01+00:00', '2040-05-07T05:07:39+00:00', '2037-07-13T07:13:45+00:00', '2066-05-20T09:00:02+00:00', '2034-04-04T06:33:37+00:00', '2041-12-24T02:53:53+00:00', '2051-01-08T13:33:35+00:00']

mal_not_before_pool = ['2021-03-01T13:08:31+00:00', '2025-04-01T12:03:11+00:00', '2025-03-28T10:15:05+00:00', '2025-08-05T11:29:04+00:00', '2025-06-13T16:58:32+00:00', '2025-08-21T05:50:24+00:00', '2025-02-24T05:40:48+00:00', '2025-08-21T10:45:30+00:00', '2025-06-19T06:12:10+00:00', '2025-08-02T10:36:30+00:00', '2025-08-12T07:28:34+00:00', '2025-07-07T05:58:47+00:00']

mal_not_after_pool = ['2035-08-10T07:28:34+00:00', '2035-03-30T12:03:11+00:00', '2048-03-22T10:15:05+00:00', '2035-02-22T05:40:48+00:00', '2035-08-19T10:45:30+00:00', '2050-06-13T06:12:10+00:00', '2048-07-17T13:08:31+00:00', '2035-08-03T11:29:04+00:00', '2035-08-19T05:50:24+00:00', '2050-06-07T16:58:32+00:00', '2035-07-05T05:58:47+00:00', '2035-07-31T10:36:30+00:00']

# Key sizes
real_key_sizes = [564, 2048, 3072, 4096]
mal_key_sizes = [512, 768, 1024, 2048, 2048]

# -------------------------------
# Helpers
# -------------------------------

def parse_subject(subject_str):
    """Extract CN, OU, O, C in multiple formats (CN=, Common Name:, etc.)."""
    parts = {}
    mappings = {
        "CN": ["CN=", "Common Name=", "Common Name:"],
        "OU": ["OU=", "Organizational Unit=", "Organizational Unit:"],
        "O": ["O=", "Organization=", "Organization:"],
        "C": ["C=", "Country=", "Country:"]
    }
    for field, variants in mappings.items():
        for v in variants:
            if v in subject_str:
                val = subject_str.split(v, 1)[1].split(",")[0].strip()
                parts[field] = val
                break
    return parts

def build_date_range(pool):
    """Convert ISO date pool to min/max datetimes."""
    dates = [datetime.fromisoformat(d) for d in pool]
    return min(dates), max(dates)

def sample_date(min_date, max_date):
    """Sample random datetime between min and max, return as ISO string."""
    delta = max_date - min_date
    rand_days = random.randint(0, delta.days)
    return (min_date + timedelta(days=rand_days)).isoformat()

def build_numeric_range(pool):
    """Get min/max for numeric values (like key_size)."""
    return min(pool), max(pool)

def sample_numeric(min_val, max_val):
    return random.choice(range(min_val, max_val + 1, 64))  # step keeps sizes reasonable

# -------------------------------
# Range Precomputation
# -------------------------------
real_nb_range = build_date_range(real_not_before_pool)
real_na_range = build_date_range(real_not_after_pool)
mal_nb_range = build_date_range(mal_not_before_pool)
mal_na_range = build_date_range(mal_not_after_pool)

real_key_range = build_numeric_range(real_key_sizes)
mal_key_range = build_numeric_range(mal_key_sizes)

# -------------------------------
# Generator
# -------------------------------
def generate_sample(is_benign=True):
    if is_benign:
        subj = random.choice(real_subjects)
        iss = random.choice(real_issuers)
        nb = sample_date(*real_nb_range)
        na = sample_date(*real_na_range)
        ks = sample_numeric(*real_key_range)
        label = "benign"
    else:
        subj = random.choice(mal_subjects)
        iss = random.choice(mal_issuers)
        nb = sample_date(*mal_nb_range)
        na = sample_date(*mal_na_range)
        ks = sample_numeric(*mal_key_range)
        label = "malicious"

    parts = parse_subject(subj)
    subj_cn = parts.get("CN", "")
    return {
        "subject": subj,
        "issuer": iss,
        "subject_common_name": subj_cn,
        "not_before": nb,
        "not_after": na,
        "key_size": ks,
        "label": label
    }

# -------------------------------
# Main CSV Writer
# -------------------------------
def generate_dataset(train_size, test_size, benign_ratio=0.7):
    train_file = OUTPUT_DIR / "certificates_train.csv"
    test_file = OUTPUT_DIR / "certificates_test.csv"

    for file, size in [(train_file, train_size), (test_file, test_size)]:
        with open(file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["subject", "issuer", "subject_common_name",
                            "not_before", "not_after", "key_size", "label"]
            )
            writer.writeheader()
            for _ in range(size):
                is_benign = random.random() < benign_ratio
                writer.writerow(generate_sample(is_benign))

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    generate_dataset(TRAIN_SAMPLES, TEST_SAMPLES, BENIGN_RATIO)
    print("✅ Certificate CSV datasets generated in", OUTPUT_DIR)
