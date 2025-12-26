**ShadowFingerprint:**

ShadowFingerprint is a forensic analytics prototype developed for the Tamil Nadu Police Hackathon 2025 under the problem statement “TOR – Unveil: Peel the Onion.”



The system does not attempt to break or decrypt TOR traffic.

Instead, it leverages behavioral correlation between:

1.Normal network PCAP logs (user-side activity)
2.Public TOR relay and exit node metadata

By correlating timing patterns, traffic fingerprints, relay reuse behavior, and circuit stability, ShadowFingerprint computes a probabilistic confidence score indicating the most likely origin IPs behind TOR-based activity.



**KEY IDEA**

TOR users do not reveal identity — but their behavior leaks patterns.

ShadowFingerprint captures these leaks and turns them into forensic clues.



**CORE FEATURES**

🛰️ PCAP Traffic Parsing

Extracts packet timing, size patterns, TTL, and encrypted flow behavior from normal network logs.

🌐 TOR Relay \& Exit Node Correlation

Matches user-side traffic bursts with observed TOR exit relay activity using temporal clustering.

🔍 Entry Node Likelihood Estimation

Identifies users exhibiting consistent, automated, or bot-like access patterns.

🛡️ Guard Node Stability Analysis

Detects stable circuit reuse — a common behavior in TOR bots and long-running attacks.

🔗 Multi-Signal Fusion Engine

Combines all signals into a single probabilistic Confidence Score.

📊 Visualization Dashboard

Interactive Streamlit UI with path graphs, timelines, suspect ranking, and forensic confidence metrics.

📄 Exportable Forensic Report

Automatically generated investigation report (PDF/JSON).



🎯 **EXPECTED OUTCOME**

Working prototype for TOR activity correlation

Visual dashboard for investigators

Probabilistic suspect ranking (not deanonymization)

Export-ready forensic evidence report



**## How to Run**



1\. Install dependencies

&nbsp;  pip install -r requirements.txt



2\. Run backend pipeline

python backend/pcap_parser.py
python backend/tor_collect.py
python backend/node_correlation.py
python backend/entry_identification.py
python backend/guard_predictor.py
python backend/fusion_engine.py
python backend/visualize_data.py
python report_generator.py
python report_to_pdf.py


3\. Launch dashboard

python -m streamlit run streamlit_app.py




⚠️ **LEGAL \& ETHICAL NOTE**



This system provides probabilistic forensic assistance only.

It does not compromise TOR anonymity and must be used strictly under legal authorization.







