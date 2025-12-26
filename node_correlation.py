# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import json
import os
from collections import defaultdict
from datetime import datetime
import math # Used for safety in logic if needed

# --------------------------------------------------
# PATHS
# --------------------------------------------------
DATA_DIR = "backend/data"
RESULTS_DIR = "backend/results"

os.makedirs(RESULTS_DIR, exist_ok=True)

PCAP_FILE = os.path.join(DATA_DIR, "pcap_parsed.json")
TOR_FILE = os.path.join(DATA_DIR, "tor_nodes.json")

OUT_PATHS = os.path.join(RESULTS_DIR, "correlated_paths.json")
OUT_TIMELINE = os.path.join(RESULTS_DIR, "timeline.json")


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def load_json(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return None
    with open(path, "r") as f:
        return json.load(f)


def normalize_ip(ip):
    return ip.split(":")[0].strip() if ip else ""


def extract_exit_ips(tor_relays):
    exit_ips = set()
    for relay in tor_relays:
        # Check both the 'exit_addresses' and potentially 'or_addresses' for IPs
        for ip in relay.get("exit_addresses", []):
            exit_ips.add(normalize_ip(ip))
    return exit_ips


# --- CORE TEMPORAL CORRELATION LOGIC (FR 2) ---
def find_temporal_match(pcap_data, current_exit_pkt, window_sec=5):
    """
    Looks for a clearnet entry flow that matches the Exit packet's metadata (JA3/TTL)
    within a small time window before the exit occurred.
    """
    exit_time = current_exit_pkt["timestamp"]
    exit_ja3 = current_exit_pkt["ja3"]
    exit_ttl = current_exit_pkt.get("ttl")
    
    # Define the search window: 5 seconds before the Exit packet (Simulating TOR latency)
    search_start = exit_time - window_sec
    
    # Track the best (highest temporal score) match
    best_match = {"matched_src_ip": None, "temporal_match_score": 0.0, "match_found": False}
    
    for pkt in pcap_data:
        # 1. Filter by Time: Only look at packets that occurred just before the exit
        if pkt["timestamp"] >= search_start and pkt["timestamp"] < exit_time:
            
            # 2. Filter by Metadata: Check for fingerprint match (Layer 2)
            if pkt.get("ja3") == exit_ja3 and pkt.get("ttl") == exit_ttl:
                
                # Found a strong temporal and metadata match
                time_diff = exit_time - pkt["timestamp"]
                
                # Temporal Score: Closer to 1.0 (perfect match) is better
                # Closer in time yields a higher score
                temporal_score = 1.0 - (time_diff / window_sec) 
                
                if temporal_score > best_match["temporal_match_score"]:
                    best_match["matched_src_ip"] = pkt["src_ip"]
                    best_match["temporal_match_score"] = temporal_score
                    best_match["match_found"] = True

    return best_match


def correlate():
    print("[+] Correlating PCAP traffic with Tor exits (FR 2)...")

    pcap_raw = load_json(PCAP_FILE)
    tor = load_json(TOR_FILE)

    if not pcap_raw or not tor:
        print("[!] Required inputs missing")
        return

    tor_exit_ips = extract_exit_ips(tor["relays"])

    correlated_paths = []
    timeline = []

    for pkt in pcap_raw:
        dst_ip = normalize_ip(pkt["dst_ip"])

        if dst_ip in tor_exit_ips:
            # --- FR 2: Perform Temporal Correlation ---
            match_result = find_temporal_match(pcap_raw, pkt, window_sec=5)

            # Only record the path if a matching entry was found temporally and via fingerprint
            if match_result["match_found"]:
                # This packet is a correlated EXIT
                correlated_paths.append({
                    "src_ip": match_result["matched_src_ip"], # Matched Entry IP (FR 6)
                    "exit_node": dst_ip,
                    "timestamp": pkt["timestamp"],
                    "readable_time": pkt["readable_time"],
                    "packet_size": pkt["length"],
                    "temporal_match_score": match_result["temporal_match_score"] # Score for fusion engine
                })

            # Record the Exit activity for the timeline visualization
            timeline.append({
                "timestamp": pkt["timestamp"],
                "time": pkt["readable_time"],
                "type": "TOR Exit",
                "ip": dst_ip
            })
        else:
            # Record the Clearnet activity (potential Entry activity)
            timeline.append({
                "timestamp": pkt["timestamp"],
                "time": pkt["readable_time"],
                "type": "Clearnet Entry",
                "ip": pkt["src_ip"]
            })

    if not correlated_paths:
        print("[!] No strong temporal correlations detected (this is valid)")
    else:
        print(f"[✓] Found {len(correlated_paths)} strong temporal-correlated paths (FR 2)")

    # Save the results
    with open(OUT_PATHS, "w") as f:
        json.dump(correlated_paths, f, indent=4)

    with open(OUT_TIMELINE, "w") as f:
        json.dump(sorted(timeline, key=lambda x: x["timestamp"]), f, indent=4)

    print(f"[✓] Saved → {OUT_PATHS}")
    print(f"[✓] Saved → {OUT_TIMELINE}")


if __name__ == "__main__":
    correlate()