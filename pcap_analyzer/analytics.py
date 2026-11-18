import pandas as pd
import numpy as np

def _numeric(series):
    return pd.to_numeric(series, errors="coerce")

def build_summary(df, metadata):
    lengths = _numeric(df.get("length", pd.Series(dtype=float))).fillna(0)
    epochs = _numeric(df.get("epoch", pd.Series(dtype=float))).dropna()
    duration = float(epochs.max() - epochs.min()) if len(epochs) > 1 else 0.0
    protocols = df.get("protocols", pd.Series(dtype=str)).fillna("")
    unique = set()
    for value in protocols:
        unique.update(x for x in str(value).split(":") if x)
    return {
        "filename": metadata.get("filename"),
        "packet_count": int(len(df)),
        "bytes_total": int(lengths.sum()),
        "duration_s": max(duration, 0.0),
        "protocol_count": len(unique),
        "protocols": sorted(unique),
        "tshark_version": metadata.get("tshark_version"),
    }

def protocol_counts(df):
    if df.empty or "protocols" not in df:
        return pd.DataFrame(columns=["protocol", "packets"])
    counts = {}
    for stack in df["protocols"].fillna(""):
        # Count the highest-level protocol in each packet's decoded stack.
        parts = [p for p in str(stack).split(":") if p]
        if parts:
            name = parts[-1]
            counts[name] = counts.get(name, 0) + 1
        else:
            counts["unknown"] = counts.get("unknown", 0) + 1
    return pd.DataFrame(
        [{"protocol": k, "packets": v} for k, v in
         sorted(counts.items(), key=lambda x: x[1], reverse=True)]
    )

def traffic_timeseries(df, bins=30):
    if df.empty or "epoch" not in df:
        return pd.DataFrame(columns=["time", "bytes"])
    data = df[["epoch", "length"]].copy()
    data["epoch"] = _numeric(data["epoch"])
    data["length"] = _numeric(data["length"]).fillna(0)
    data = data.dropna(subset=["epoch"])
    if data.empty:
        return pd.DataFrame(columns=["time", "bytes"])
    if data["epoch"].nunique() == 1:
        return pd.DataFrame([{"time": pd.to_datetime(data["epoch"].iloc[0], unit="s"), "bytes": int(data["length"].sum())}])
    data["time"] = pd.to_datetime(data["epoch"], unit="s", utc=True)
    data = data.set_index("time").sort_index()
    rule = f"{max(1, int(np.ceil((data.index.max()-data.index.min()).total_seconds()/bins)))}s"
    return data["length"].resample(rule).sum().rename("bytes").reset_index()

def top_talkers(df, limit=15):
    if df.empty or "src" not in df:
        return pd.DataFrame(columns=["source", "packets", "bytes"])
    work = df.copy()
    work["length"] = _numeric(work["length"]).fillna(0)
    out = (work.dropna(subset=["src"])
           .groupby("src", as_index=False)
           .agg(packets=("src", "size"), bytes=("length", "sum"))
           .sort_values("bytes", ascending=False).head(limit))
    return out.rename(columns={"src": "source"})

def _transport(row):
    p = str(row.get("protocols", "")).lower()
    if "tcp" in p:
        return "TCP", row.get("tcp_sport"), row.get("tcp_dport"), row.get("tcp_stream")
    if "udp" in p:
        return "UDP", row.get("udp_sport"), row.get("udp_dport"), row.get("udp_stream")
    if "sctp" in p:
        return "SCTP", row.get("sctp_sport"), row.get("sctp_dport"), None
    return None, None, None, None

def calculate_flow_kpis(df):
    columns = ["flow", "packets", "bytes", "duration_s", "throughput_mbps",
               "mean_interarrival_ms", "jitter_indicator_ms"]
    if df.empty:
        return pd.DataFrame(columns=columns)
    work = df.copy()
    work["epoch"] = _numeric(work["epoch"])
    work["length"] = _numeric(work["length"]).fillna(0)
    work = work.dropna(subset=["epoch", "src", "dst"])
    if work.empty:
        return pd.DataFrame(columns=columns)

    keys = []
    for _, row in work.iterrows():
        proto, sport, dport, stream = _transport(row)
        keys.append((str(row["src"]), str(row["dst"]), proto or "IP",
                     str(sport or ""), str(dport or ""),
                     str(stream or "")))
    work["flow_key"] = keys
    results = []
    for key, group in work.groupby("flow_key", sort=False):
        group = group.sort_values("epoch")
        times = group["epoch"].to_numpy(dtype=float)
        diffs = np.diff(times) * 1000
        diffs = diffs[diffs >= 0]
        duration = max(float(times[-1] - times[0]), 0.0) if len(times) else 0.0
        total_bytes = int(group["length"].sum())
        throughput = (total_bytes * 8 / duration / 1_000_000) if duration > 0 else 0.0
        mean_iat = float(np.mean(diffs)) if len(diffs) else 0.0
        jitter = float(np.mean(np.abs(np.diff(diffs)))) if len(diffs) > 1 else 0.0
        results.append({
            "flow": f"{key[0]}:{key[3]} → {key[1]}:{key[4]} ({key[2]})",
            "packets": int(len(group)), "bytes": total_bytes,
            "duration_s": round(duration, 6),
            "throughput_mbps": round(throughput, 6),
            "mean_interarrival_ms": round(mean_iat, 4),
            "jitter_indicator_ms": round(jitter, 4),
        })
    return pd.DataFrame(results, columns=columns).sort_values("bytes", ascending=False)

def build_callflow(df, limit=2000):
    if df.empty:
        return pd.DataFrame(columns=["time", "frame", "source", "destination", "protocol", "event"])
    candidates = []
    for _, row in df.iterrows():
        stack = str(row.get("protocols", "")).lower()
        # Protocol-specific fields are flattened into the packet dataframe.
        raw = row.to_dict()
        event_parts = []
        if "ngap" in stack:
            event_parts.append("NGAP")
        if "nas_5gs" in stack or "nas-5gs" in stack:
            event_parts.append("NAS-5GS")
        if "pfcp" in stack:
            event_parts.append("PFCP")
        if not event_parts:
            continue
        detail = []
        for key, value in raw.items():
            if value and any(token in key.lower() for token in
                             ("message_type", "procedurecode", "procedure_code", "msg_type")):
                detail.append(f"{key}={value}")
        candidates.append({
            "time": row.get("time"), "epoch": row.get("epoch"),
            "frame": row.get("frame"), "source": row.get("src"),
            "destination": row.get("dst"),
            "protocol": " / ".join(event_parts),
            "event": "; ".join(detail) if detail else "Protocol observed; message detail unavailable"
        })
        if len(candidates) >= limit:
            break
    out = pd.DataFrame(candidates)
    if not out.empty:
        out = out.sort_values("epoch", na_position="last").drop(columns=["epoch"])
    return out
