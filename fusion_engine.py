# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================

import json
import os
from collections import defaultdict
from datetime import datetime
import math # Added for safe max/min operations

# --------------------------------------------------
# PATHS
# --------------------------------------------------
RESULTS_DIR = "backend/results"
os.makedirs(RESULTS_DIR, exist_ok=True)

CORRELATED_FILE = os.path.join(RESULTS_DIR, "correlated_paths.json")
ENTRY_FILE = os.path.join(RESULTS_DIR, "entry_nodes.json")
GUARD_FILE = os.path.join(RESULTS_DIR, "guard_nodes.json")

SCORES_FILE = os.path.join(RESULTS_DIR, "scores.json")
SUSPECTS_FILE = os.path.join(RESULTS_DIR, "suspects.json")
REPORT_FILE = os.path.join(RESULTS_DIR, "forensic_report.json")


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def compute_session_spread(correlated):
    """
    Computes session duration (last_seen - first_seen) per user
    Used as a tie-breaker signal
    """
    times = defaultdict(list)

    for pkt in correlated:
        if "timestamp" in pkt:
            times[pkt["src_ip"]].append(pkt["timestamp"])

    spread = {}
    for user, ts in times.items():
        if len(ts) > 1:
            spread[user] = max(ts) - min(ts)
        else:
            spread[user] = 0

    return spread

def load_json(path):
    if not os.path.exists(path):
        print(f"[!] Missing file: {path}")
        return []
    with open(path, "r") as f:
        return json.load(f)

# --------------------------------------------------
# STEP 1.5: SESSION SPREAD BONUS (Tie-breaker)
# --------------------------------------------------


def normalize_scores(score_dict, base=0.55, scale=0.40):
    """
    Normalize raw scores into forensic-friendly confidence range: 0.60 – 0.95.
    (FR 4: Confidence Scoring)
    """
    if not score_dict:
        return {}

    # Use a large number if the dictionary contains non-numeric zero values, 
    # but math.fsum is safer for floating point addition.
    max_val = max(score_dict.values())
    
    if max_val == 0:
        return {k: base for k in score_dict}

    return {
        k: round(base + (v / max_val) * scale, 4) # Increased precision for component scores
        for k, v in score_dict.items()
    }

def compute_first_seen_offset(correlated):
    """
    Computes how early a user's Tor activity started.
    Earlier start = slightly higher suspicion.
    """
    first_seen = {}

    for pkt in correlated:
        user = pkt.get("src_ip")
        ts = pkt.get("timestamp")
        if user and ts:
            if user not in first_seen:
                first_seen[user] = ts
            else:
                first_seen[user] = min(first_seen[user], ts)

    if not first_seen:
        return {}

    min_ts = min(first_seen.values())
    max_ts = max(first_seen.values())

    offsets = {}
    for user, ts in first_seen.items():
        if max_ts == min_ts:
            offsets[user] = 0.0
        else:
            # Normalized tiny bonus: 0.0 – 0.01
            offsets[user] = round((max_ts - ts) / (max_ts - min_ts) * 0.01, 6)

    return offsets

# --------------------------------------------------
# FUSION ENGINE
# --------------------------------------------------
def fusion_score_engine():
    print("[+] Computing fusion-based suspect scores (FR 4)...")

    correlated = load_json(CORRELATED_FILE)
    entry_nodes = load_json(ENTRY_FILE)
    guard_nodes = load_json(GUARD_FILE)

    first_seen_bonus = compute_first_seen_offset(correlated)

    if not correlated:
        print("[!] Correlated traffic missing. Cannot score suspects.")
        return
    
    spread_raw = compute_session_spread(correlated)
    spread_score = normalize_scores(
        spread_raw,
        base=0.00,
        scale=0.05
    ) 
    
    # --------------------------------------------------
    # STEP 1: TEMPORAL BEHAVIOR SCORE (FR 2)
    # Uses 'temporal_match_score' (from node_correlation.py) strength
    # --------------------------------------------------
    temporal_raw = defaultdict(float)
    for pkt in correlated:
        # Sum the temporal match strength for each user
        temporal_raw[pkt["src_ip"]] += pkt.get("temporal_match_score", 0)

    temporal_score = normalize_scores(temporal_raw)

    # --------------------------------------------------
    # STEP 2: ENTRY NODE SCORE (FR 3)
    # --------------------------------------------------
    entry_raw = defaultdict(float)
    for entry in entry_nodes:
        # Assumes 'entry_score' is a raw score calculated in entry_identification.py
        entry_raw[entry["user_ip"]] += entry.get("entry_score", 0)

    entry_score = normalize_scores(entry_raw)

    # --------------------------------------------------
    # STEP 3: GUARD NODE STABILITY SCORE (FR 6)
    # --------------------------------------------------
    guard_raw = defaultdict(float)
    # guard_nodes contains pre-calculated confidence scores
    for g in guard_nodes:
        guard_raw[g["user_ip"]] += g.get("confidence", 0)

    guard_score = normalize_scores(guard_raw, base=0.55, scale=0.30)

    # --------------------------------------------------
    # STEP 4: FUSION (WEIGHTED + CLAMPED)
    # --------------------------------------------------
    WEIGHTS = {
        "temporal": 0.60, # Weight for timing/pattern match
        "entry": 0.25,    # Weight for automated behavior/frequency
        "guard": 0.15     # Weight for stable circuit reuse
    }

    users = set(temporal_score) | set(entry_score) | set(guard_score)
    suspects = []

    for user in users:
        # Get component scores, default to the BASE of the normalization if metric is missing
        t_score = temporal_score.get(user, 0.6)
        e_score = entry_score.get(user, 0.6)
        g_score = guard_score.get(user, 0.55) 

        # Calculate final weighted score
        fs_bonus = first_seen_bonus.get(user, 0.0)

        final = (
            t_score * WEIGHTS["temporal"]
            + e_score * WEIGHTS["entry"]
            + g_score * WEIGHTS["guard"]
            + fs_bonus
        )


        # Clamp confidence to realistic forensic bounds (0.95 max)
        final = min(final, 0.95)

        # EO 2: Save full breakdown for suspect ranking table
        suspects.append({
            "user_ip": user,
            "temporal_score": round(t_score, 4),
            "entry_score": round(e_score, 4),
            "guard_score": round(g_score, 4),
            "final_score": final
        })

    suspects.sort(key=lambda x: x["final_score"], reverse=True)

    # --------------------------------------------------
    # STEP 5: SAVE OUTPUTS (EO 3)
    # --------------------------------------------------
    with open(SCORES_FILE, "w") as f:
        json.dump(suspects, f, indent=4)

    with open(SUSPECTS_FILE, "w") as f:
        json.dump(suspects, f, indent=4)

    # --------------------------------------------------
    # STEP 6: FORENSIC REPORT (EO 3)
    # --------------------------------------------------
    top = suspects[0] if suspects else None

    report = {
        "case_metadata": {
            "case_id": f"TNCCW-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_on": datetime.now().isoformat(),
            "unit": "Cyber Crime Wing, Tamil Nadu Police"
        },
        "case_overview": (
            "This report presents a probabilistic forensic analysis of Tor-based "
            "network traffic. The system correlates PCAP-derived behavior with "
            "Tor relay metadata to identify likely origin candidates without "
            "compromising Tor anonymity."
        ),
        "analysis_methodology": [
            "PCAP traffic parsing and behavioral feature extraction: Extracts TTL, packet size, and JA3 signatures (FR 5).",
            "Tor exit relay correlation and temporal activity clustering: Links clearnet entry activity to observed Tor exit activity based on timing and pattern (FR 2).",
            "Entry node likelihood estimation: Scores users based on consistent/automated network behavior (FR 3).",
            "Guard node stability analysis: Scores users based on stable circuit/exit node reuse (FR 6).",
            "Multi-signal weighted fusion scoring: Combines all signals into a single probabilistic Confidence Score (FR 4)."
        ],
        "key_findings": {
            "total_suspects": len(suspects),
            "top_suspect": top["user_ip"] if top else None,
            "confidence_score": round(top["final_score"], 4) if top else None # FIX: Saves the score as 0.XX (0-1), correcting the 8760.0% error.
        },
        "suspect_ranking": suspects,
        "legal_notice": (
            "This analysis provides probabilistic indicators only. "
            "It does not deanonymize Tor users and must be used strictly "
            "within legal authorization and judicial oversight."
        )
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[✓] Saved scores → {SCORES_FILE}")
    print(f"[✓] Saved suspects → {SUSPECTS_FILE}")
    print(f"[✓] Saved forensic report → {REPORT_FILE}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------
if __name__ == "__main__":
    fusion_score_engine()