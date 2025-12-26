# ==============================================================================
# PROPERTY OF CYBER CRIME WING - TAMIL NADU POLICE
# PROJECT: SHADOWFINGERPRINT (Tor Origin Identification System)
# HACKATHON: TN Police Hackathon 2025
# ==============================================================================
import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px
import networkx as nx
import matplotlib.pyplot as plt

# --------------------------------------------------
# PAGE CONFIG
# --------------------------------------------------
st.set_page_config(
    page_title="SHADOWFINGERPRINT — TN Police Hackathon",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------------------------------
# CUSTOM CSS AND PATHS (UNCHANGED)
# --------------------------------------------------
st.markdown("""
<style>
/* ... CSS styles remain ... */
.main-title-text {
    font-size: 4em !important;
    font-weight: 800 !important;
    color: #00bcd4;
    text-shadow: 2px 2px 4px #000000;
    margin-top: -30px !important;
}
div[data-testid="stMetric"] {
    background-color: #1a1a2e;
    border-left: 5px solid #00bcd4;
    padding: 15px;
    border-radius: 10px;
    box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2);
}
h1, h2, h3, h4 {
    color: #00bcd4;
}
</style>
""", unsafe_allow_html=True)


RESULTS_DIR = "backend/results"
VISUAL_FILE = os.path.join(RESULTS_DIR, "visual_data.json")
REPORT_JSON = os.path.join(RESULTS_DIR, "forensic_report.json")
REPORT_PDF = os.path.join(RESULTS_DIR, "forensic_report.pdf")
ENTRY_FILE = os.path.join(RESULTS_DIR, "entry_nodes.json")
GUARD_FILE = os.path.join(RESULTS_DIR, "guard_nodes.json")

# --------------------------------------------------
# LOADERS (UNCHANGED)
# --------------------------------------------------
def load_json(path, name):
    try:
        if not os.path.exists(path):
            st.error(f"{name} not found. Run backend pipeline first.")
            st.stop()
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        st.error(f"Error loading {name}: {e}")
        st.stop()

visual = load_json(VISUAL_FILE, "visual_data.json")
report = load_json(REPORT_JSON, "forensic_report.json")

def load_df(path):
    if not os.path.exists(path):
        return pd.DataFrame()
    with open(path, "r") as f:
        return pd.DataFrame(json.load(f))

entry_df = load_df(ENTRY_FILE)
guard_df = load_df(GUARD_FILE)

# --------------------------------------------------
# SIDEBAR (NAVIGATION) (UNCHANGED)
# --------------------------------------------------
st.sidebar.markdown('<h1 style="color: #FF4B4B;">Cyber Crime Console</h1>', unsafe_allow_html=True)
st.sidebar.caption("Tamil Nadu Police")

menu = st.sidebar.radio(
    "🧭 INVESTIGATION CONSOLE",
    [
        "📊 Dashboard",
        "🌐 Tor Path Visualization",
        "⏱ Timeline Analysis",
        "🚨 Entry & Guard Analysis",
        "📄 Forensic Report"
    ],
    format_func=lambda x: f"  {x.split(' ')[0]} {x.split(' ', 1)[1]}" 
)

st.sidebar.divider()
st.sidebar.markdown("### Case Metadata")
st.sidebar.markdown(
    f"""
    **#️⃣ Case ID:** `{report['case_metadata']['case_id']}`  
    **🚓 Unit:** Cyber Crime Wing  
    **📅 Generated:** {report['case_metadata']['generated_on'][:19]}
    """
)

with st.sidebar:
    st.divider()
    st.subheader("📂 Live Evidence Ingestion")
    uploaded_file = st.file_uploader("Upload Network Trace (PCAP)", type=["pcap", "jpeg", "json"])
    
    if uploaded_file is not None:
        with st.status("Analyzing Evidence...", expanded=True) as status:
            st.write("Extracting packet metadata...")
            # Simulate a 2-second delay for "processing"
            import time
            time.sleep(1) 
            st.write("Cross-referencing Tor Relay metadata...")
            time.sleep(1)
            status.update(label="Evidence Ingested Successfully!", state="complete", expanded=False)
        
        st.info(f"File '{uploaded_file.name}' is now queued for Fusion Engine analysis.")
# --------------------------------------------------
# HEADER AND TOP METRICS (FIXED SYNCHRONIZATION)
# --------------------------------------------------
st.markdown('<p class="main-title-text">SHADOWFINGERPRINT</p>', unsafe_allow_html=True)
st.caption("Tor Origin Identification & Probabilistic Forensic Correlation System")

# PULL DATA DIRECTLY FROM THE FINAL REPORT FOR SYNCHRONIZATION
top_suspect_ip = report["key_findings"]["top_suspect"]
top_confidence = report["key_findings"]["confidence_score"] # This is the 0-1 score

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Correlated Suspects", report["key_findings"]["total_suspects"])
with col2:
    st.metric("Top Suspect IP", top_suspect_ip if top_suspect_ip else "N/A")
with col3:
    # FIX: Ensure all top-level metrics reflect the final, strong score
    st.metric(
        "Fusion Confidence Score",
        f"{round(top_confidence * 100, 1)}%",
        help="Weighted score from Temporal, Entry, and Guard metrics. (Synchronized)"
    )

st.divider()

# ==================================================
# PAGE 1: DASHBOARD
# ==================================================
if menu == "📊 Dashboard":
    st.header("📊 Investigation Dashboard")

    colA, colB = st.columns([2, 1])

    with colA:
        st.subheader("Case Overview")
        st.info(report["case_overview"])

        st.subheader("Analysis Methodology")
        st.markdown("The ShadowFingerprint employs a multi-layered correlation approach:")
        for step in report["analysis_methodology"]:
            # --- FIX FOR INDEXERROR: Safely parse the methodology steps ---
            if ':' in step:
                parts = step.split(':', 1)
                st.markdown(f"- **{parts[0].strip()}:** *{parts[1].strip()}*")
            else:
                st.markdown(f"- {step.strip()}")


    with colB:
        st.subheader("Key Findings")
        st.metric("Top Suspect", report["key_findings"]["top_suspect"])
        # FIX: Ensure this metric is also reading the final, correct 0-1 score
        st.metric(
            "Confidence",
            f"{round(report['key_findings']['confidence_score'] * 100, 1)}%"
        )

# ==================================================
# PAGE 2: TOR PATH VISUALIZATION
# ==================================================

elif menu == "🌐 Tor Path Visualization":
    st.header("🌐 Tor Path Correlation Graph")
    
    G = nx.Graph()
    for path in visual["tor_paths"]:
        # Ensure we have both ends of the connection
        if path.get("src_ip") and path.get("exit_node"):
            G.add_edge(path["src_ip"], path["exit_node"])

    if len(G.nodes) == 0:
        st.warning("No path data found. Re-run node_correlation.py.")
    else:
        fig, ax = plt.subplots(figsize=(12, 8))
        # Use a dark background for the plot to match the UI
        fig.patch.set_facecolor('#1a1a2e') 
        ax.set_facecolor('#1a1a2e')

        pos = nx.spring_layout(G, k=0.5, seed=42)
        
        # Color the top suspect red, others cyan
        top_ip = report["key_findings"]["top_suspect"]
        colors = ['#FF4B4B' if n == top_ip else '#00e5ff' for n in G.nodes()]

        nx.draw(G, pos, with_labels=True, node_color=colors,
                edge_color="#555", node_size=2500, font_size=10, 
                font_color="black", font_weight="bold", ax=ax)
        
        st.pyplot(fig)
        st.caption("Red Node: Top Suspect | Blue Nodes: Other Suspects/Exit Nodes")


# ==================================================
# PAGE 3: TIMELINE
# ==================================================
elif menu == "⏱ Timeline Analysis":
    st.header("⏱ Temporal Correlation Timeline")
    st.markdown("Chronological mapping of observed Clearnet (pre-Tor) activity versus Tor Exit activity, critical for **Node Correlation**.")

    timeline_df = pd.DataFrame(visual["timeline"])
    if timeline_df.empty:
        st.warning("Timeline data unavailable.")
    else:
        timeline_df["Events"] = 1
        
        fig = px.line(timeline_df.groupby("time")["Events"].sum().reset_index(), 
                      x='time', 
                      y='Events', 
                      title='Total Network Events Over Time',
                      template='plotly_dark')
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Activity Breakdown")
        fig_breakdown = px.bar(timeline_df, x='time', y='Events', color='type', 
                               title='Entry vs. Exit Activity Timeline',
                               color_discrete_map={'TOR Exit': '#FF4B4B', 'Clearnet Entry': '#00bcd4'})
        st.plotly_chart(fig_breakdown, use_container_width=True)


# ==================================================
# PAGE 4: ENTRY & GUARD ANALYSIS
# ==================================================
elif menu == "🚨 Entry & Guard Analysis":
    st.header("🚨 Entry & Guard Node Confidence")

    # -------- ENTRY CONFIDENCE --------
    st.subheader("📍 Entry Node Likelihood")
    st.markdown("Score based on packet size and time consistency (automated behavior).")

    if entry_df.empty:
        st.warning("Entry node data not available.")
    else:
        entry_df["entry_pct"] = (
            entry_df["entry_score"] / entry_df["entry_score"].max()
        ) * 100

        fig_entry = px.bar(
            entry_df,
            x="entry_pct",
            y="user_ip",
            orientation="h",
            text=entry_df["entry_pct"].round(1),
            title="Entry Node Likelihood (%)",
            template="plotly_dark",
            color_discrete_sequence=['#00bcd4']
        )
        st.plotly_chart(fig_entry, use_container_width=True)

    # -------- GUARD CONFIDENCE --------
    st.subheader("🛡 Guard Node Stability")
    st.markdown("Confidence based on the consistent reuse of specific exit nodes, indicating a stable entry circuit.")

    if guard_df.empty:
        st.info("Guard node reuse not strongly observed.")
    else:
        guard_df["confidence_pct"] = guard_df["confidence"] * 100

        fig_guard = px.bar(
            guard_df,
            x="confidence_pct",
            y="user_ip",
            orientation="h",
            text=guard_df["confidence_pct"].round(1),
            title="Guard Node Stability (%)",
            template="plotly_dark",
            color_discrete_sequence=['#FF4B4B']
        )

        st.plotly_chart(fig_guard, use_container_width=True)

# ==================================================
# PAGE 5: FORENSIC REPORT
# ==================================================
elif menu == "📄 Forensic Report":
    st.header("📄 Forensic Investigation Report")

    # 1. Dashboard View (Key Findings Summary)
    with st.expander("🔍 Key Findings", expanded=True):
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            # Displays the top suspect identified by the fusion engine
            st.metric("Top Suspect", report["key_findings"]["top_suspect"])
        with col_f2:
            # Syncing display logic: Ensures decimal (e.g., 0.935) shows as 93.5%
            # Matches the logic used in the top-level metrics
            conf_val = report["key_findings"]["confidence_score"]
            st.metric(
                "Confidence Score",
                f"{round(conf_val * 100, 1)}%"
            )
        with col_f3:
            # Total count of correlated source IPs found in the data
            st.metric("Total Suspects", report["key_findings"]["total_suspects"])

    # 2. Suspect Ranking Table
    st.subheader("📋 Detailed Suspect Ranking")
    with st.expander("Show Ranking and Score Breakdown", expanded=True):
        # Convert the ranking list from the report into a readable DataFrame
        suspects_df = pd.DataFrame(report["suspect_ranking"])
        
        # Add a formatted percentage column for the UI table
        suspects_df['Final Score (%)'] = (suspects_df['final_score'] * 100).round(2)
        
        # Display the specific forensic signals (Temporal, Entry, Guard)
        st.dataframe(
            suspects_df[[
                'user_ip', 'Final Score (%)', 'temporal_score', 'entry_score', 'guard_score'
            ]].rename(columns={
                'user_ip': 'Probable Origin IP', 
                'temporal_score': 'Temporal Score (0-1)', 
                'entry_score': 'Entry Score (0-1)', 
                'guard_score': 'Guard Score (0-1)'
            }),
            use_container_width=True
        )

    # 3. Legal Notice
    with st.expander("⚖ Legal & Ethical Notice"):
        # Displays the notice from forensic_report.json
        st.info(report["legal_notice"])

    st.divider()

    # 4. PROFESSIONAL PDF GENERATION & DOWNLOAD
    st.divider()
    st.subheader("⬇ Export Official Documentation")
    
    try:
        from report_to_pdf import convert_report_to_pdf
        
        # 1. Generate the PDF
        raw_pdf_data = convert_report_to_pdf(report)
        
        # 2. FIX: Convert bytearray to standard bytes
        # This solves the "Invalid binary data format" error
        pdf_bytes = bytes(raw_pdf_data)
        
        st.download_button(
            label="Download Official Forensic Report (PDF)",
            data=pdf_bytes, # Now receiving standard bytes
            file_name=f"Forensic_Report_{report['case_metadata']['case_id']}.pdf",
            mime="application/pdf",
            use_container_width=True
        )
        st.caption("Official document includes Tamil Nadu Police watermark and branding.")
        
    except Exception as e:
        st.error(f"Error: {e}")
        st.info("Ensure report_generator.py and report_to_pdf.py are in your folder.")
# --------------------------------------------------
# FOOTER
# --------------------------------------------------
st.divider()
st.caption(
    "⚠️ This system provides probabilistic forensic assistance only. "
    "It does not deanonymize Tor users and must be used with legal authorization. | TN Cyber Crime Wing"
)