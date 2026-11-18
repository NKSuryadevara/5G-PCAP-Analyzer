from datetime import datetime, timezone
from .analytics import protocol_counts, top_talkers

def make_report(df, summary, metadata, warnings):
    protocols = protocol_counts(df).to_dict(orient="records")
    talkers = top_talkers(df).to_dict(orient="records")
    return {
        "application": "5G-PCAP Analyzer",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture": summary,
        "metadata": metadata,
        "protocol_distribution": protocols,
        "top_talkers": talkers,
        "warnings": warnings,
        "interpretation_notes": [
            "Protocol decoding depends on capture visibility and installed TShark dissectors.",
            "A PCAP may not contain all interfaces or all packets in a procedure.",
            "One-way latency requires synchronised clocks and appropriate capture points.",
            "Generic packet timing indicators must not be treated as 3GPP QoS guarantees."
        ]
    }
