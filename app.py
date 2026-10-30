import streamlit as st
import pandas as pd
import time
from datetime import datetime
from pathlib import Path

from scanner import scan_directory
from synthesizer import synthesize_traps
from database import save_trap, get_all_traps, get_all_alerts
from anomaly_detector import run_pipeline, AnomalyDetectorConfig, IsolationForestAnomalyDetector

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SpectreSync | Autonomous Deception Mesh",
    page_icon="S",
    layout="wide",
)

# ── Dark tactical theme via custom CSS ───────────────────────────────────────
st.markdown(
    """
    <style>
    /* Global dark background overrides */
    .stApp {
        background-color: #0a0e17;
        color: #c9d1d9;
    }

    /* Header / title styling */
    h1, h2, h3, h4 {
        color: #00ffae !important;
        font-family: 'Courier New', monospace;
    }

    /* Tab label styling */
    .stTabs [data-baseweb="tab-list"] button {
        color: #8b949e;
        font-family: 'Courier New', monospace;
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab-list"] button[aria-selected="true"] {
        color: #00ffae;
        border-bottom-color: #00ffae;
    }

    /* Input field styling */
    .stTextInput > div > div > input {
        background-color: #161b22;
        color: #c9d1d9;
        border: 1px solid #30363d;
    }

    /* Button styling */
    .stButton > button {
        background-color: #00ffae;
        color: #0a0e17;
        font-weight: 700;
        border: none;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
    }
    .stButton > button:hover {
        background-color: #00cc8b;
        color: #0a0e17;
    }

    /* Dataframe / table styling */
    .stDataFrame, .stTable {
        background-color: #161b22;
    }

    /* Status log container */
    .status-log {
        background-color: #0d1117;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 1rem;
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        color: #8b949e;
        max-height: 400px;
        overflow-y: auto;
    }
    .status-log .log-success { color: #00ffae; }
    .status-log .log-warn    { color: #f0c040; }
    .status-log .log-info    { color: #58a6ff; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── Helper: render a styled log line ─────────────────────────────────────────
def _log(container, message: str, level: str = "info") -> None:
    """Write a timestamped log entry into the given Streamlit container."""
    css_class = f"log-{level}"
    stamp = datetime.now().strftime("%H:%M:%S")
    container.markdown(
        f'<div class="status-log"><span class="{css_class}">'
        f"[{stamp}] {message}"
        f"</span></div>",
        unsafe_allow_html=True,
    )


# ── App title ────────────────────────────────────────────────────────────────
st.markdown("# SpectreSync | Autonomous Deception Mesh")
st.caption("Active Defense -- Dynamic Trap Synthesis -- Threat Entanglement")

# ── Tabs ─────────────────────────────────────────────────────────────────────
tab_deploy, tab_soc, tab_anomaly = st.tabs(["Mesh Deployment", "SOC Threat Stream", "Threat Anomaly Detection (ML)"])


# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 1 -- Mesh Deployment
# ═══════════════════════════════════════════════════════════════════════════════
with tab_deploy:
    st.subheader("Deploy Deception Mesh")

    target_path = st.text_input(
        "Target Repository / Folder Path",
        placeholder="/home/user/project  or  C:\\Projects\\MyRepo",
        help="Absolute path to the codebase SpectreSync will instrument with traps.",
    )

    deploy_btn = st.button("Deploy SpectreSync", use_container_width=True)

    st.divider()
    st.subheader("Deployment Status Log")
    log_container = st.container()

    if deploy_btn:
        if not target_path.strip():
            st.error("Please provide a valid target repository path.")
        elif not Path(target_path).is_dir():
            st.error(f"Directory not found: {target_path}")
        else:
            # Phase 1 -- Scan
            _log(log_container, "Scanning repository structure...", "info")
            _log(log_container, f"   Target: `{target_path}`", "info")
            time.sleep(0.6)

            try:
                scan_report = scan_directory(target_path)
            except Exception as exc:
                st.error(f"Scanner error: {exc}")
                st.stop()

            file_count = len(scan_report.get("scanned_files", []))
            env_count = len(scan_report.get("env_vars", []))
            key_count = len(scan_report.get("config_keys", []))
            _log(log_container,
                 f"Scan complete -- {file_count} sensitive files, "
                 f"{env_count} env vars, {key_count} config keys found.", "info")
            time.sleep(0.4)

            # Phase 2 -- Synthesize
            _log(log_container, "Synthesizing adaptive honeytokens...", "warn")
            time.sleep(0.5)

            trap_output = synthesize_traps(scan_report)
            trap_list = trap_output.get("traps", [])
            _log(log_container,
                 f"Generated {len(trap_list)} context-aware decoy traps.", "warn")
            time.sleep(0.4)

            # Phase 3 -- Persist to database
            _log(log_container, "Storing traps in local database...", "info")
            time.sleep(0.3)

            saved_count = 0
            for trap in trap_list:
                try:
                    save_trap(
                        trap_name=trap["variable_name"],
                        trap_type=trap["category"],
                        target_path=str(target_path),
                        endpoint_url=trap["endpoint"],
                    )
                    saved_count += 1
                except Exception:
                    # Duplicate endpoint_url (UNIQUE constraint) -- skip
                    pass

            _log(log_container,
                 f"Persisted {saved_count} new traps ({len(trap_list) - saved_count} "
                 f"duplicates skipped).", "info")
            time.sleep(0.3)

            # Phase 4 -- Done
            _log(log_container, "Activating telemetry beacons...", "info")
            time.sleep(0.5)
            _log(log_container, "SpectreSync mesh deployed successfully.", "success")

    # ── Active traps summary ─────────────────────────────────────────────────
    st.divider()
    st.subheader("Active Traps")

    all_traps = get_all_traps()
    if all_traps:
        traps_df = pd.DataFrame(all_traps)
        display_cols = ["id", "trap_name", "trap_type", "target_path", "endpoint_url", "created_at"]
        traps_df = traps_df[[c for c in display_cols if c in traps_df.columns]]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Traps", len(traps_df))
        col2.metric("Unique Types", traps_df["trap_type"].nunique() if "trap_type" in traps_df.columns else 0)
        col3.metric("Target Paths", traps_df["target_path"].nunique() if "target_path" in traps_df.columns else 0)

        st.dataframe(
            traps_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "trap_name": st.column_config.TextColumn("Trap Name", width="large"),
                "trap_type": st.column_config.TextColumn("Type", width="small"),
                "target_path": st.column_config.TextColumn("Target Path", width="medium"),
                "endpoint_url": st.column_config.TextColumn("Endpoint", width="medium"),
                "created_at": st.column_config.TextColumn("Created At", width="medium"),
            },
        )
    else:
        st.info("No traps deployed yet. Enter a target path above and click Deploy.")


# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 2 -- SOC Threat Stream
# ═══════════════════════════════════════════════════════════════════════════════
with tab_soc:
    st.subheader("Live Security Alerts")

    # Auto-refresh toggle
    auto_refresh = st.toggle("Auto-refresh (every 10s)", value=False)
    if auto_refresh:
        st.caption("Alerts will refresh automatically.")

    refresh_btn = st.button("Refresh Now", use_container_width=True)

    alerts = get_all_alerts()

    if alerts:
        alerts_df = pd.DataFrame(alerts)
        display_cols = ["id", "trap_name", "timestamp", "source_ip", "user_agent", "status"]
        alerts_df = alerts_df[[c for c in display_cols if c in alerts_df.columns]]

        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Alerts", len(alerts_df))
        col2.metric("Triggered", len(alerts_df[alerts_df["status"] == "Triggered"]))
        col3.metric("Unique IPs", alerts_df["source_ip"].nunique() if "source_ip" in alerts_df.columns else 0)
        col4.metric("Traps Hit", alerts_df["trap_name"].nunique() if "trap_name" in alerts_df.columns else 0)

        st.dataframe(
            alerts_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "trap_name": st.column_config.TextColumn("Trap Name", width="large"),
                "timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                "source_ip": st.column_config.TextColumn("Source IP", width="small"),
                "user_agent": st.column_config.TextColumn("User Agent", width="medium"),
                "status": st.column_config.TextColumn("Status", width="small"),
            },
        )
    else:
        st.info("No alerts recorded yet. Alerts appear here when a canary trap is triggered.")

    # Trigger auto-refresh via st.rerun after a delay
    if auto_refresh:
        time.sleep(10)
        st.rerun()


# ═══════════════════════════════════════════════════════════════════════════════
#  TAB 3 -- Threat Anomaly Detection (Isolation Forest ML Engine)
# ═══════════════════════════════════════════════════════════════════════════════
with tab_anomaly:
    st.subheader("Isolation Forest Threat Anomaly Detection")
    st.caption("Unsupervised Machine Learning for Zero-Day Attack Discovery & Network Flow Outlier Detection")

    col_ctrl1, col_ctrl2, col_ctrl3, col_ctrl4 = st.columns(4)
    with col_ctrl1:
        sample_size = st.select_slider(
            "Analysis Sample Size",
            options=[5000, 10000, 20000, 50000, 100000, 0],
            value=20000,
            format_func=lambda x: "Full Dataset" if x == 0 else f"{x:,} Flows",
            help="Number of network flow records to ingest. Subsampling accelerates real-time inference.",
        )
    with col_ctrl2:
        contamination = st.slider(
            "Contamination Rate",
            min_value=0.01,
            max_value=0.25,
            value=0.10,
            step=0.01,
            help="Expected ratio of anomalous/outlier instances in the network flow traffic.",
        )
    with col_ctrl3:
        n_estimators = st.slider(
            "Ensemble Trees",
            min_value=50,
            max_value=250,
            value=150,
            step=25,
            help="Number of isolation decision trees built in the forest.",
        )
    with col_ctrl4:
        scaler_choice = st.selectbox(
            "Feature Scaler",
            options=["robust", "standard"],
            index=0,
            help="RobustScaler uses Median and IQR, ensuring extreme attack outliers do not skew normalization.",
        )

    run_detection_btn = st.button("Run Anomaly Detection Pipeline", use_container_width=True)

    results_csv = Path("data/spectresync_anomaly_results.csv")
    results_json = Path("data/spectresync_anomaly_results_summary.json")

    results_df = None
    if run_detection_btn:
        with st.spinner("Executing Isolation Forest pipeline (Preprocessing -> Scaler -> IF Ensemble -> Root Cause Attribution)..."):
            try:
                results_df, summary = run_pipeline(
                    sample_size=sample_size if sample_size > 0 else None,
                    contamination=contamination,
                    n_estimators=n_estimators,
                    scaler_type=scaler_choice,
                    output_dir="data",
                )
                st.success("Anomaly detection pipeline executed successfully!")
            except Exception as exc:
                st.error(f"Error executing anomaly detection: {exc}")
                results_df = None

    elif results_csv.exists():
        results_df = pd.read_csv(results_csv)
        st.info(f"Loaded existing detection results from `{results_csv}` ({len(results_df):,} records). Click above to re-run.")

    if results_df is not None and not results_df.empty:
        total_eval = len(results_df)
        anomaly_count = int((results_df["anomaly_prediction"] == -1).sum())
        normal_count = int((results_df["anomaly_prediction"] == 1).sum())
        anomaly_pct = round((anomaly_count / total_eval) * 100, 2)
        critical_count = int((results_df["anomaly_severity"] == "CRITICAL_ANOMALY").sum())

        st.divider()
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Evaluated Flows", f"{total_eval:,}")
        m2.metric("Normal Inliers", f"{normal_count:,}", f"{100 - anomaly_pct:.1f}%")
        m3.metric("Flagged Anomalies", f"{anomaly_count:,}", f"{anomaly_pct:.1f}%", delta_color="inverse")
        m4.metric("Critical Threat Anomalies", f"{critical_count:,}", delta_color="inverse")

        # Ground truth breakdown if present
        if "label" in results_df.columns:
            st.markdown("#### Ground-Truth Threat Detection Breakdown")
            ctab = pd.crosstab(results_df["label"], results_df["prediction_label"])
            if "ANOMALY" in ctab.columns:
                ctab["Anomaly Detection Rate (%)"] = (ctab["ANOMALY"] / ctab.sum(axis=1) * 100).round(1)
            st.dataframe(ctab, use_container_width=True)

        st.markdown("#### Flagged Anomaly Stream & Root-Cause Attribution")
        anomalies_only = results_df[results_df["anomaly_prediction"] == -1].copy()

        view_cols = ["record_id", "anomaly_severity", "threat_risk_percent", "anomaly_score", "primary_root_cause", "supporting_features"]
        if "label" in anomalies_only.columns:
            view_cols.insert(1, "label")

        st.dataframe(
            anomalies_only[[c for c in view_cols if c in anomalies_only.columns]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "record_id": st.column_config.TextColumn("Flow ID", width="small"),
                "label": st.column_config.TextColumn("Ground Truth", width="small"),
                "anomaly_severity": st.column_config.TextColumn("Severity", width="small"),
                "threat_risk_percent": st.column_config.ProgressColumn("Threat Risk Index", format="%.1f%%", min_value=0, max_value=100),
                "anomaly_score": st.column_config.NumberColumn("Raw Decision Score", format="%.4f"),
                "primary_root_cause": st.column_config.TextColumn("Primary Root Cause", width="medium"),
                "supporting_features": st.column_config.TextColumn("Supporting Features (z-score deviation)", width="large"),
            },
        )
