# 5G-PCAP Analyzer

A Streamlit Community Cloud application for offline analysis of PCAP/PCAPNG files using TShark.

## Features

- PCAP and PCAPNG upload
- TShark-backed packet dissection
- Ethernet, IPv4/IPv6, TCP, UDP and SCTP metadata
- Dynamic extraction of available NGAP, NAS-5GS, GTP and PFCP fields
- Protocol distribution, traffic time series and top talkers
- Flow-level throughput, inter-arrival and jitter indicators
- Time-ordered signalling-event view
- CSV and JSON exports
- Optional password gate using Streamlit secrets

## Important limitations

This is an advanced research prototype, not a certified 3GPP conformance analyser.

- It can only decode fields visible in the capture and supported by the deployed TShark version.
- NAS and application payloads protected by encryption/integrity may not be readable.
- Ordinary N2/N3 Ethernet captures do not expose the full Uu radio stack.
- Correlating a UE's control-plane identity with its user-plane TEID requires appropriate signalling context; this prototype does not claim complete automatic UE/session correlation.
- Throughput is calculated from observed bytes and capture duration. One-way latency requires synchronised clocks and suitable capture points.
- The jitter indicator is a descriptive inter-arrival variation, not a formal RTP/3GPP QoS metric.
- Packet loss is not inferred generically from missing packet numbers. TCP retransmission fields may be added when available.

