# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import json
import os
import random
from datetime import datetime, timedelta

DATA_DIR = "backend/data"
os.makedirs(DATA_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(DATA_DIR, "pcap_parsed.json")

INTERNAL_IPS = [
    "192.168.1.50",
    "192.168.1.51",
    "192.168.1.52",
    "192.168.1.53"
]

TOR_EXIT_IPS = [
    "98.12.34.56",
    "185.220.101.1",
    "199.249.230.71"
]

def generate_synthetic_pcap():
    packets = []
    base_time = datetime.now() - timedelta(minutes=10)

    for i in range(60):
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(TOR_EXIT_IPS + ["8.8.8.8", "1.1.1.1"])

        timestamp = base_time + timedelta(seconds=i * random.randint(2, 6))

        packets.append({
            "timestamp": int(timestamp.timestamp()),
            "readable_time": timestamp.strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "length": random.randint(400, 1500),
            "ttl": random.choice([64, 128]),
            "tcp_window": random.randint(1000, 65000),
            "ja3": f"JA3_{random.randint(1,5)}"
        })

    with open(OUTPUT_FILE, "w") as f:
        json.dump(packets, f, indent=4)

    print(f"[✓] Generated synthetic PCAP data → {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_synthetic_pcap()
