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

## Local installation (Ubuntu 22.04/24.04)

```bash
sudo apt update
sudo apt install -y tshark python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`.

## Deploy to Streamlit Community Cloud

1. Create a GitHub repository named `5G-PCAP-Analyzer`.
2. Upload all files and folders from this project to the repository root.
3. Do not commit PCAP/PCAPNG captures or secrets.
4. Visit https://share.streamlit.io/ and sign in with GitHub.
5. Select **Create app**.
6. Select the repository, branch (usually `main`) and `app.py`.
7. In Advanced settings, choose a supported Python version (Python 3.12 is a suitable target).
8. Deploy. Streamlit installs Python packages from `requirements.txt` and Linux packages from `packages.txt`.
9. Check app logs if TShark installation or dependency resolution fails.

Official documentation:
- https://docs.streamlit.io/deploy/streamlit-community-cloud
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/app-dependencies
- https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy

## Optional password protection

In Streamlit Community Cloud, open the app's **Settings > Secrets** and add:

```toml
APP_PASSWORD = "use-a-long-unique-password"
```

The application then asks for this password before showing the upload interface. Do not commit `secrets.toml` to GitHub.

If no password is configured, the app is accessible to anyone who has its URL. A password gate is a basic access barrier, not a substitute for institutional identity management or a security review.

## Testing

```bash
pip install -r requirements.txt
pytest -q
```

Check TShark and protocol fields:

```bash
tshark --version
tshark -G protocols | grep -Ei 'ngap|nas|gtp|pfcp|sctp'
tshark -G fields | grep -Ei 'ngap\\.|nas_5gs\\.|gtp\\.|pfcp\\.'
```

Test a capture locally:

```bash
tshark -r sample.pcap -c 100 -T fields \
  -e frame.number -e frame.time_epoch -e frame.protocols \
  -e ip.src -e ip.dst -e gtp.teid
```

## Suggested test captures

Use small, synthetic or anonymised captures that you are authorised to analyse:
- N2: NGAP over SCTP
- N3: GTP-U over UDP (commonly UDP port 2152)
- N4: PFCP over UDP (commonly UDP port 8805)
- N6: application traffic from the UPF towards a data network

A single capture may not contain all these interfaces. A capture with no 5G packets should still display general packet metadata.

## Free-tier operating model

This project uses Streamlit Community Cloud's free hosting and open-source Python/TShark components. It has no paid API dependency and no separately managed VM.

Free hosting is shared and resource-limited. This repository sets a conservative 100 MB upload cap and a configurable packet-processing limit. Large captures can exceed memory, CPU or execution-time limits. The service's terms, quotas and availability may change; zero recurring cost is a target, not a service-level guarantee.

## Data handling and privacy

- Captures are written to a temporary file and removed after processing.
- Results are held in the running app session; do not rely on this as durable storage.
- Avoid uploading real SUPI/IMSI, MSISDN, subscriber IP, authentication, location or customer traffic.
- Do not upload restricted institutional or operator data to a public cloud without written approval.
- Use a private institutional deployment for sensitive or large captures.

## Repository layout

```text
5G-PCAP-Analyzer/
├── app.py
├── requirements.txt
├── packages.txt
├── README.md
├── .gitignore
├── .streamlit/
│   └── config.toml
├── pcap_analyzer/
│   ├── __init__.py
│   ├── engine.py
│   ├── analytics.py
│   └── reporting.py
└── tests/
    └── test_analytics.py
```

## Roadmap

1. Validate field names against the deployed TShark build and representative lab captures.
2. Add protocol-specific NGAP/NAS/PFCP message dictionaries and procedure-state tracking.
3. Add reliable control-plane/user-plane correlation using observed identifiers and timing.
4. Add configurable anonymisation and richer export formats.
5. Add regression tests with synthetic PCAP fixtures.
