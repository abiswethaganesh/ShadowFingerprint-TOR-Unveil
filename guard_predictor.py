# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import json
import os
from collections import defaultdict

# --------------------------------------------------
# PATHS
# --------------------------------------------------
RESULTS_DIR = "backend/results"

CORRELATED_FILE = os.path.join(RESULTS_DIR, "correlated_paths.json")
ENTRY_FILE = os.path.join(RESULTS_DIR, "entry_nodes.json")
OUTPUT_FILE = os.path.join(RESULTS_DIR, "guard_nodes.json")


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def load_json(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return []
    with open(path, "r") as f:
        return json.load(f)


# --------------------------------------------------
# GUARD NODE PREDICTION
# --------------------------------------------------
def predict_guard_nodes():
    print("[+] Refining guard node prediction...")

    correlated = load_json(CORRELATED_FILE)
    entry_nodes = load_json(ENTRY_FILE)

    if not correlated or not entry_nodes:
        print("[!] Required inputs missing")
        return

    # --------------------------------------------------
    # STEP 1: Identify candidate users (top entry nodes)
    # --------------------------------------------------
    candidate_users = {e["user_ip"] for e in entry_nodes[:5]}

    # --------------------------------------------------
    # STEP 2: Track exit stability per user
    # Guard logic: fewer exits used repeatedly = higher confidence
    # --------------------------------------------------
    stability = defaultdict(lambda: defaultdict(int))

    for pkt in correlated:
        user = pkt.get("src_ip")
        exit_node = pkt.get("exit_node") or pkt.get("dst_ip")

        if user in candidate_users and exit_node:
            stability[user][exit_node] += 1

    # --------------------------------------------------
    # STEP 3: Compute guard confidence
    # --------------------------------------------------
    guard_predictions = []

    for user, exits in stability.items():
        total = sum(exits.values())
        unique_exits = len(exits)

        if total == 0:
            continue

        # Guard behavior:
        # Fewer exits + more reuse = more stable = more suspicious
        stability_ratio = max(1, total / max(unique_exits, 1))

        for exit_node, count in exits.items():
            confidence = round(
                (count / total) * (stability_ratio / 5), 3
            )

            guard_predictions.append({
                "user_ip": user,
                "guard_node": exit_node,
                "connection_count": count,
                "confidence": min(confidence, 1.0)
            })

    guard_predictions.sort(
        key=lambda x: (x["user_ip"], -x["confidence"])
    )

    # --------------------------------------------------
    # STEP 4: SAVE OUTPUT
    # --------------------------------------------------
    with open(OUTPUT_FILE, "w") as f:
        json.dump(guard_predictions, f, indent=4)

    print(f"[✓] Saved refined guard predictions → {OUTPUT_FILE}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == "__main__":
    predict_guard_nodes()
