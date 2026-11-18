import json
import hmac
import streamlit as st
import pandas as pd
import plotly.express as px

from pcap_analyzer.engine import (
    check_tshark, analyze_capture, tshark_version, available_5g_fields
)
from pcap_analyzer.analytics import (
    build_summary, protocol_counts, traffic_timeseries, top_talkers,
    build_callflow, calculate_flow_kpis
)
from pcap_analyzer.reporting import make_report

st.set_page_config(
    page_title="5G-PCAP Analyzer",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

MAX_UPLOAD_MB = 100
MAX_PACKETS = 100_000

def access_gate():
    """Optional password gate. Configure APP_PASSWORD in Streamlit secrets."""
    expected = st.secrets.get("APP_PASSWORD", "") if hasattr(st, "secrets") else ""
    if not expected:
        st.sidebar.warning(
            "No APP_PASSWORD is configured. Anyone with the app URL may access it. "
            "Use synthetic/anonymised captures only."
        )
        return True
    if st.session_state.get("authenticated"):
        return True
    st.title("5G-PCAP Analyzer")
    st.info("This deployment is password protected.")
    supplied = st.text_input("Access password", type="password")
    if st.button("Sign in"):
        if hmac.compare_digest(supplied, str(expected)):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    return False

def main():
    st.title("📡 5G-PCAP Analyzer")
    st.caption("Cloud-based offline packet dissection and 5G protocol analytics")
    if not access_gate():
        st.stop()

    with st.sidebar:
        st.header("Analysis settings")
        max_packets = st.number_input(
            "Maximum packets to process",
            min_value=1_000, max_value=MAX_PACKETS,
            value=25_000, step=1_000,
            help="A cap protects the shared free application from memory/time exhaustion."
        )
        st.caption(f"Upload cap: {MAX_UPLOAD_MB} MB")
        st.caption("Analysis is performed in a temporary workspace; files are deleted after processing.")

    status = check_tshark()
    if not status["available"]:
        st.error("TShark is not available in this runtime.")
        st.code(status.get("error", "Install Wireshark/TShark."))
        st.stop()

    with st.expander("Runtime information"):
        st.write(f"**TShark:** {tshark_version()}")
        st.write(f"**5G dissector fields detected:** {len(available_5g_fields())}")
        st.caption("Field availability depends on the TShark/Wireshark version and enabled dissectors.")

    uploaded = st.file_uploader(
        "Upload a packet capture",
        type=["pcap", "pcapng"],
        help="Use a capture you are authorised to analyse. Avoid uploading subscriber-identifiable traffic."
    )
    if uploaded is None:
        st.markdown("""
        ### What this prototype analyses
        - Ethernet, IPv4/IPv6, TCP, UDP and SCTP packet metadata
        - NGAP, NAS-5GS, GTP/GTP-U and PFCP fields when present and supported
        - Protocol distribution, traffic endpoints, time series and indicative flow KPIs
        - Time-ordered signalling-event view and CSV/JSON exports
        """)
        st.info("Start with a small, synthetic or anonymised PCAP (preferably below 20 MB).")
        return

    if uploaded.size > MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"File exceeds this deployment's {MAX_UPLOAD_MB} MB safety limit.")
        st.stop()

    st.write(f"**Selected file:** {uploaded.name} · {uploaded.size / (1024*1024):.2f} MB")
    if not st.button("🔍 Analyse PCAP", type="primary"):
        return

    progress = st.progress(0, text="Preparing capture...")
    try:
        result = analyze_capture(
            uploaded.getvalue(),
            filename=uploaded.name,
            max_packets=int(max_packets),
            progress_callback=lambda n, total: progress.progress(
                min(0.95, n / max(total, 1)), text=f"Dissecting packets: {n:,}"
            ),
        )
        progress.progress(1.0, text="Analysis complete")
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        st.exception(exc)
        st.stop()

    df = result["packets"]
    if df.empty:
        st.warning("No packets were returned by TShark. Check that the file is a valid PCAP/PCAPNG.")
        return

    summary = build_summary(df, result["metadata"])
    st.success(f"Processed {len(df):,} packets.")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Packets", f"{summary['packet_count']:,}")
    k2.metric("Captured data", f"{summary['bytes_total']/1024/1024:.2f} MB")
    k3.metric("Capture duration", f"{summary['duration_s']:.3f} s")
    k4.metric("Protocols", f"{summary['protocol_count']:,}")

    tab_overview, tab_packets, tab_5g, tab_flows, tab_callflow, tab_export = st.tabs([
        "Overview", "Packet explorer", "5G protocols", "Traffic & KPIs",
        "Signalling events", "Export"
    ])

    with tab_overview:
        left, right = st.columns(2)
        counts = protocol_counts(df)
        if not counts.empty:
            left.subheader("Protocol distribution")
            left.plotly_chart(
                px.pie(counts, names="protocol", values="packets", hole=0.45),
                use_container_width=True
            )
        ts = traffic_timeseries(df)
        right.subheader("Traffic over time")
        if not ts.empty:
            right.plotly_chart(
                px.line(ts, x="time", y="bytes", title="Bytes per time bucket"),
                use_container_width=True
            )
        st.subheader("Top endpoints")
        talkers = top_talkers(df)
        if not talkers.empty:
            st.dataframe(talkers, use_container_width=True, hide_index=True)

    with tab_packets:
        st.subheader("Decoded packet metadata")
        filters = ["All packets", "NGAP", "NAS-5GS", "GTP/GTP-U", "PFCP", "TCP", "UDP", "SCTP"]
        selected = st.selectbox("Protocol quick filter", filters)
        view = df
        if selected != "All packets":
            token = {
                "NGAP": "ngap", "NAS-5GS": "nas", "GTP/GTP-U": "gtp",
                "PFCP": "pfcp", "TCP": "tcp", "UDP": "udp", "SCTP": "sctp"
            }[selected]
            view = df[df["protocols"].str.lower().str.contains(token, na=False)]
        st.caption(f"{len(view):,} matching packets")
        st.dataframe(view, use_container_width=True, height=480, hide_index=True)

    with tab_5g:
        st.subheader("5G protocol field extraction")
        for label, prefix in [
            ("NGAP", "ngap."), ("NAS-5GS", "nas_5gs."),
            ("GTP / GTP-U", "gtp."), ("PFCP", "pfcp.")
        ]:
            cols = [c for c in df.columns if c.startswith(prefix)]
            with st.expander(f"{label} · {len(cols)} extracted fields", expanded=(len(cols) > 0)):
                if cols:
                    subset = df.loc[df[cols].notna().any(axis=1), ["frame", "time", "src", "dst", "protocols"] + cols]
                    st.dataframe(subset, use_container_width=True, height=300, hide_index=True)
                else:
                    st.caption("No matching fields were observed or supported in this capture.")

    with tab_flows:
        st.subheader("Flow-level indicators")
        flow_kpis = calculate_flow_kpis(df)
        if not flow_kpis.empty:
            st.dataframe(flow_kpis, use_container_width=True, hide_index=True)
            st.caption(
                "These are capture-derived indicators, not guaranteed end-to-end QoS measurements. "
                "One-way latency requires synchronised capture clocks and suitable observation points."
            )
        else:
            st.info("Insufficient IP/transport metadata to construct flow indicators.")

    with tab_callflow:
        st.subheader("Time-ordered signalling events")
        events = build_callflow(df)
        if events.empty:
            st.info("No NGAP/NAS-5GS/PFCP signalling event labels were identified.")
        else:
            st.dataframe(events, use_container_width=True, height=450, hide_index=True)
            st.caption(
                "This is an event timeline, not a standards-complete UE procedure state machine. "
                "Protected or absent messages cannot be reconstructed."
            )

    with tab_export:
        st.subheader("Download analysis")
        csv_data = df.to_csv(index=False).encode("utf-8")
        report = make_report(df, summary, result["metadata"], result["warnings"])
        st.download_button("Download packet analysis CSV", csv_data,
                           "5g_pcap_packets.csv", "text/csv")
        st.download_button("Download summary JSON",
                           json.dumps(report, indent=2, default=str).encode("utf-8"),
                           "5g_pcap_report.json", "application/json")
        st.download_button("Download signalling events CSV",
                           build_callflow(df).to_csv(index=False).encode("utf-8"),
                           "5g_signalling_events.csv", "text/csv")
        if result["warnings"]:
            st.warning("Analysis notes")
            for warning in result["warnings"]:
                st.write(f"- {warning}")

    st.caption("5G-PCAP Analyzer · Research prototype · Validate findings against the original capture/Wireshark.")

if __name__ == "__main__":
    main()
