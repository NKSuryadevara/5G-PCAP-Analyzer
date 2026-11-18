import pandas as pd
from pcap_analyzer.analytics import build_summary, protocol_counts, calculate_flow_kpis

def sample():
    return pd.DataFrame([
        {"frame":"1","epoch":100.0,"time":"t1","length":100,"src":"10.0.0.1","dst":"10.0.0.2",
         "protocols":"eth:ip:udp:gtp:gtp","udp_sport":"2152","udp_dport":"2152",
         "tcp_sport":None,"tcp_dport":None,"sctp_sport":None,"sctp_dport":None,
         "tcp_stream":None,"udp_stream":"0","raw_fields":{}},
        {"frame":"2","epoch":100.1,"time":"t2","length":200,"src":"10.0.0.1","dst":"10.0.0.2",
         "protocols":"eth:ip:udp:gtp:gtp","udp_sport":"2152","udp_dport":"2152",
         "tcp_sport":None,"tcp_dport":None,"sctp_sport":None,"sctp_dport":None,
         "tcp_stream":None,"udp_stream":"0","raw_fields":{}},
    ])

def test_summary():
    s = build_summary(sample(), {"filename":"x.pcap"})
    assert s["packet_count"] == 2
    assert s["bytes_total"] == 300
    assert round(s["duration_s"], 2) == 0.1

def test_protocol_counts():
    counts = protocol_counts(sample())
    assert int(counts["packets"].sum()) == 2

def test_flow_kpis():
    result = calculate_flow_kpis(sample())
    assert len(result) == 1
    assert int(result.iloc[0]["packets"]) == 2
