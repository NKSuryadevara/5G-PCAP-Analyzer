import csv
import io
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

BASE_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.time",
    "frame.len", "frame.protocols",
    "eth.src", "eth.dst",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "ip.proto", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "sctp.srcport", "sctp.dstport",
    "tcp.stream", "udp.stream", "sctp.assoc_index",
    "tcp.len", "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission", "tcp.analysis.lost_segment",
    "gtp.teid", "gtp.message", "gtp.message_type",
    "pfcp.msg_type", "pfcp.seid",
    "ngap.procedureCode", "ngap.procedure_code",
    "nas_5gs.mm.message_type", "nas_5gs.sm.message_type",
]

FIVE_G_PREFIXES = ("ngap.", "nas_5gs.", "gtp.", "pfcp.")
MAX_DYNAMIC_FIELDS = 32
COMMAND_TIMEOUT = 240

def _run(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)

def check_tshark():
    path = shutil.which("tshark")
    if not path:
        return {"available": False, "error": "tshark executable not found in PATH"}
    try:
        proc = _run([path, "--version"], timeout=10)
        return {"available": proc.returncode == 0, "error": proc.stderr.strip()}
    except Exception as exc:
        return {"available": False, "error": str(exc)}

def tshark_version():
    if not shutil.which("tshark"):
        return "Not installed"
    p = _run(["tshark", "--version"], timeout=10)
    return (p.stdout.splitlines()[0] if p.stdout else p.stderr.strip())

def available_5g_fields():
    if not shutil.which("tshark"):
        return []
    p = _run(["tshark", "-G", "fields"], timeout=30)
    found = []
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            field = parts[2]
            if field.startswith(FIVE_G_PREFIXES):
                found.append(field)
    return found

def _select_fields():
    if not shutil.which("tshark"):
        raise RuntimeError("TShark is not installed.")
    p = _run(["tshark", "-G", "fields"], timeout=30)
    available = set()
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            available.add(parts[2])
    fields = [f for f in BASE_FIELDS if f in available]
    dynamic = sorted(
        f for f in available
        if f.startswith(FIVE_G_PREFIXES)
        and f not in fields
    )
    # Prefer useful message/identity/tunnel/QoS fields, while bounding output width.
    priority_terms = ("message", "procedure", "teid", "seid", "qfi", "5qi",
                      "pdu", "cause", "ran_ue", "amf_ue", "guti", "supi")
    dynamic.sort(key=lambda x: (not any(t in x.lower() for t in priority_terms), x))
    fields.extend(dynamic[:MAX_DYNAMIC_FIELDS])
    # Keep frame number and protocols available for all packet rows.
    return list(dict.fromkeys(fields))

def _normalise_cell(value):
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None

def analyze_capture(file_bytes, filename="capture.pcap", max_packets=25000,
                    progress_callback=None):
    """Run TShark safely with argv (no shell), parse tab-separated fields."""
    if not file_bytes:
        raise ValueError("The uploaded file is empty.")
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise ValueError("Only .pcap and .pcapng files are accepted.")
    if not shutil.which("tshark"):
        raise RuntimeError("TShark is unavailable. Install the Linux package 'tshark'.")

    fields = _select_fields()
    if not fields:
        raise RuntimeError("TShark did not expose the expected packet fields.")

    warnings = []
    with tempfile.NamedTemporaryFile(suffix=Path(filename).suffix.lower(), delete=False) as tmp:
        tmp.write(file_bytes)
        capture_path = tmp.name

    try:
        args = [
            "tshark", "-n", "-r", capture_path,
            "-c", str(int(max_packets)),
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=/t",
            "-E", "quote=d",
            "-E", "occurrence=a",
            "-E", "aggregator=;",
        ]
        for field in fields:
            args.extend(["-e", field])

        proc = subprocess.run(
            args, capture_output=True, text=True,
            timeout=COMMAND_TIMEOUT, check=False
        )
        if proc.returncode != 0:
            message = proc.stderr.strip() or "TShark returned a non-zero exit status."
            raise RuntimeError(message[-3000:])

        reader = csv.DictReader(io.StringIO(proc.stdout), delimiter="\t", quotechar='"')
        rows = []
        for idx, row in enumerate(reader, start=1):
            cleaned = {k: _normalise_cell(v) for k, v in row.items() if k}
            # Stable application-level columns.
            protocols = cleaned.get("frame.protocols") or ""
            src = cleaned.get("ip.src") or cleaned.get("ipv6.src")
            dst = cleaned.get("ip.dst") or cleaned.get("ipv6.dst")
            epoch = cleaned.get("frame.time_epoch")
            try:
                epoch = float(epoch) if epoch else None
            except ValueError:
                epoch = None
            try:
                length = int(float(cleaned.get("frame.len") or 0))
            except ValueError:
                length = 0
            record = {
                "frame": cleaned.get("frame.number") or str(idx),
                "epoch": epoch,
                "time": cleaned.get("frame.time"),
                "length": length,
                "src": src,
                "dst": dst,
                "protocols": protocols,
                "tcp_sport": cleaned.get("tcp.srcport"),
                "tcp_dport": cleaned.get("tcp.dstport"),
                "udp_sport": cleaned.get("udp.srcport"),
                "udp_dport": cleaned.get("udp.dstport"),
                "sctp_sport": cleaned.get("sctp.srcport"),
                "sctp_dport": cleaned.get("sctp.dstport"),
                "tcp_stream": cleaned.get("tcp.stream"),
                "udp_stream": cleaned.get("udp.stream"),
                "gtp_teid": cleaned.get("gtp.teid"),
                "raw_fields": cleaned,
            }
            rows.append(record)
            if progress_callback and idx % 500 == 0:
                progress_callback(idx, max_packets)

        if len(rows) >= max_packets:
            warnings.append(
                f"Packet processing limit reached ({max_packets:,}). "
                "The remaining capture packets were not analysed."
            )
        if proc.stderr.strip():
            warnings.append(proc.stderr.strip()[-1500:])

        import pandas as pd
        records = []
        for row in rows:
            flat = {k: v for k, v in row.items() if k != "raw_fields"}
            flat.update(row["raw_fields"])
            records.append(flat)
        df = pd.DataFrame(records)
        metadata = {
            "filename": Path(filename).name,
            "file_size_bytes": len(file_bytes),
            "fields_extracted": fields,
            "tshark_version": tshark_version(),
            "packet_limit": int(max_packets),
        }
        return {"packets": df, "metadata": metadata, "warnings": warnings}
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"TShark exceeded the {COMMAND_TIMEOUT}-second processing timeout. "
            "Try a smaller capture or lower packet limit."
        )
    finally:
        try:
            os.remove(capture_path)
        except OSError:
            pass
