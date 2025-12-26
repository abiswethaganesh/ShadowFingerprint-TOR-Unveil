# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================


import json
import os
from collections import defaultdict
import statistics

RESULTS_DIR = "backend/results"

CORRELATED_FILE = os.path.join(RESULTS_DIR, "correlated_paths.json")
OUT_FILE = os.path.join(RESULTS_DIR, "entry_nodes.json")


def load_json(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return None
    with open(path, "r") as f:
        return json.load(f)


def identify_entry_nodes():
    print("[+] Identifying probable entry/origin nodes...")

    paths = load_json(CORRELATED_FILE)
    if not paths:
        print("[!] No correlated paths available")
        return

    stats = defaultdict(lambda: {
        "connections": 0,
        "packet_sizes": [],
        "timestamps": []
    })

    # -----------------------------------
    # Aggregate behavior per source IP
    # -----------------------------------
    for p in paths:
        src = p["src_ip"]
        stats[src]["connections"] += 1
        stats[src]["packet_sizes"].append(p["packet_size"])
        stats[src]["timestamps"].append(p["timestamp"])

    results = []

    # -----------------------------------
    # Scoring logic (forensic-friendly)
    # -----------------------------------
    for ip, data in stats.items():
        freq_score = data["connections"]

        size_variance = (
            statistics.pvariance(data["packet_sizes"])
            if len(data["packet_sizes"]) > 1 else 0
        )

        time_gaps = [
            t2 - t1
            for t1, t2 in zip(
                sorted(data["timestamps"])[:-1],
                sorted(data["timestamps"])[1:]
            )
        ]
        time_consistency = (
            statistics.pvariance(time_gaps)
            if len(time_gaps) > 1 else 0
        )

        # Lower variance = more automation = more suspicious
        score = (
            freq_score * 2
            + max(0, 1000 - size_variance)
            + max(0, 1000 - time_consistency)
        )

        results.append({
            "user_ip": ip,
            "connections": freq_score,
            "size_variance": round(size_variance, 2),
            "time_variance": round(time_consistency, 2),
            "entry_score": round(score, 2)
        })

    # Sort by suspicion score
    results.sort(key=lambda x: x["entry_score"], reverse=True)

    with open(OUT_FILE, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[✓] Saved entry node predictions → {OUT_FILE}")


if __name__ == "__main__":
    identify_entry_nodes()
