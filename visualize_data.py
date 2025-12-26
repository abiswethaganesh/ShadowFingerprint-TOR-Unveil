# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import json
import os
from collections import defaultdict

RESULTS_DIR = "backend/results"

CORRELATED_FILE = os.path.join(RESULTS_DIR, "correlated_paths.json")
TIMELINE_FILE = os.path.join(RESULTS_DIR, "timeline.json")
ENTRY_FILE = os.path.join(RESULTS_DIR, "entry_nodes.json")
GUARD_FILE = os.path.join(RESULTS_DIR, "guard_nodes.json")
SUSPECTS_FILE = os.path.join(RESULTS_DIR, "suspects.json")

OUTPUT_FILE = os.path.join(RESULTS_DIR, "visual_data.json")


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


def build_visual_data():
    print("[+] Creating visualization JSON...")

    correlated = load_json(CORRELATED_FILE)
    timeline = load_json(TIMELINE_FILE)
    entry_nodes = load_json(ENTRY_FILE)
    guard_nodes = load_json(GUARD_FILE)
    suspects = load_json(SUSPECTS_FILE)

    # -----------------------------------------
    # Tor path visualization
    # -----------------------------------------
    tor_paths = []
    for pkt in correlated:
        tor_paths.append({
            "src_ip": pkt.get("src_ip"),
            "exit_node": pkt.get("exit_node") or pkt.get("dst_ip"),
            "time": pkt.get("readable_time")
        })

    # -----------------------------------------
    # Entry confidence grouping
    # -----------------------------------------
    entry_confidence = defaultdict(list)
    for entry in entry_nodes:
        entry_confidence[entry["user_ip"]].append({
            "confidence": entry.get("confidence", 0)
        })

    # -----------------------------------------
    # Guard confidence grouping (optional)
    # -----------------------------------------
    guard_confidence = defaultdict(list)
    for guard in guard_nodes:
        guard_confidence[guard["user_ip"]].append({
            "exit_node": guard.get("exit_node"),
            "confidence": guard.get("confidence", 0)
        })

    # -----------------------------------------
    # Suspect ranking (simplified)
    # -----------------------------------------
    suspect_ranking = []
    for s in suspects:
        suspect_ranking.append({
            "user_ip": s["user_ip"],
            "score": s["final_score"]
        })

    # -----------------------------------------
    # Summary
    # -----------------------------------------
    summary = {
        "total_suspects": len(suspect_ranking),
        "highest_score": suspect_ranking[0] if suspect_ranking else {}
    }

    visual_data = {
        "summary": summary,
        "tor_paths": tor_paths,
        "timeline": timeline,
        "entry_confidence": entry_confidence,
        "guard_confidence": guard_confidence,
        "suspect_ranking": suspect_ranking
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(visual_data, f, indent=4)

    print(f"[✓] Visualization JSON saved → {OUTPUT_FILE}")


if __name__ == "__main__":
    build_visual_data()
