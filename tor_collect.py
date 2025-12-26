# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import requests
import json
import os
import random
from datetime import datetime

DATA_DIR = "backend/data"
os.makedirs(DATA_DIR, exist_ok=True)

TOR_FILE = os.path.join(DATA_DIR, "tor_nodes.json")
PCAP_FILE = os.path.join(DATA_DIR, "pcap_parsed.json")


def load_pcap_ips():
    """
    Extract destination IPs from parsed PCAP
    Used to align synthetic Tor exits with observed traffic
    """
    if not os.path.exists(PCAP_FILE):
        return []

    with open(PCAP_FILE, "r") as f:
        packets = json.load(f)

    dst_ips = list(
        set(pkt["dst_ip"].split(":")[0] for pkt in packets if pkt.get("dst_ip"))
    )

    return dst_ips


def fetch_real_tor_relays():
    """
    Fetch real Tor relay metadata from Onionoo
    """
    print("[+] Fetching real Tor relay metadata from Onionoo…")
    url = "https://onionoo.torproject.org/details?type=relay"

    response = requests.get(url, timeout=10)
    response.raise_for_status()

    data = response.json()

    relays = []
    for r in data.get("relays", []):
        relays.append({
            "fingerprint": r.get("fingerprint"),
            "nickname": r.get("nickname"),
            "flags": r.get("flags", []),
            "or_addresses": r.get("or_addresses", []),
            "exit_addresses": r.get("exit_addresses", []),
            "last_seen": r.get("last_seen"),
            "advertised_bandwidth": r.get("advertised_bandwidth", 0)
        })

    print(f"[✓] Retrieved {len(relays)} real Tor relays")
    return relays


def generate_synthetic_tor_exits():
    """
    Generate Tor exits aligned with PCAP destination IPs
    (for demo / offline environments)
    """
    print("[!] Onionoo unavailable — using PCAP-aligned synthetic exits")

    pcap_ips = load_pcap_ips()
    if not pcap_ips:
        print("[!] No PCAP IPs available, cannot generate synthetic exits")
        return []

    exits = random.sample(pcap_ips, min(5, len(pcap_ips)))

    relays = []
    for i, ip in enumerate(exits):
        relays.append({
            "fingerprint": f"SYNTHETIC_EXIT_{i}",
            "nickname": f"SyntheticExit{i}",
            "flags": ["Exit", "Fast", "Running"],
            "or_addresses": [f"{ip}:9001"],
            "exit_addresses": [ip],
            "last_seen": datetime.utcnow().isoformat(),
            "advertised_bandwidth": random.randint(100_000, 900_000)
        })

    print(f"[✓] Generated {len(relays)} synthetic Tor exits aligned with PCAP")
    return relays


def main():
    try:
        relays = fetch_real_tor_relays()
    except Exception:
        relays = generate_synthetic_tor_exits()

    with open(TOR_FILE, "w") as f:
        json.dump({"relays": relays}, f, indent=4)

    print(f"[✓] Tor relay data saved → {TOR_FILE}")


if __name__ == "__main__":
    main()
