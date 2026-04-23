

import pandas as pd
import numpy as np
import joblib
import json
import os
import time
import threading
import subprocess
from datetime import datetime

from Backend.config import Config

import logging
logger = logging.getLogger("smart_alert.ml")

KBEST_FEATURES = [
    'Dst Port', 'Protocol', 'Fwd Packet Length Min', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Fwd IAT Std', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd Packets/s',
    'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Bwd Segment Size Avg', 'Bwd Bulk Rate Avg', 'Subflow Fwd Packets',
    'Subflow Bwd Bytes', 'FWD Init Win Bytes', 'Fwd Seg Size Min',
    'Active Mean', 'Active Min', 'Idle Std'
]

logger.info("Loading model artifacts...")
try:
    model = joblib.load(Config.MODEL_PATH)
    scaler = joblib.load(Config.SCALER_PATH)
    le = joblib.load(Config.ENCODER_PATH)
    logger.info(f"Model loaded. Classes: {list(le.classes_)}")
    print(f"[ML] Model loaded — {len(le.classes_)} classes")
except Exception as e:
    logger.error(f"Failed to load model artifacts: {e}")
    print(f"[ML] ERROR loading model: {e}")
    model = scaler = le = None

_latest_rows = []
_latest_counts = {}
_live_running = False
_live_lock = threading.Lock()


def predict_dataframe(df: pd.DataFrame) -> list[dict]:
   
    if model is None or scaler is None or le is None:
        raise RuntimeError("Model artifacts not loaded. Check file paths in .env")

    df.columns = df.columns.str.strip()

    meta_cols = ['src_ip', 'dst_ip', 'timespan', 'Src IP', 'Dst IP', 'Timestamp']
    meta = {}
    for col in meta_cols:
        if col in df.columns:
            meta[col] = df[col].copy()

    missing = [f for f in KBEST_FEATURES if f not in df.columns]
    if missing:
        logger.warning(f"Missing features {missing} — filling with scaler mean")

    X = df.reindex(columns=KBEST_FEATURES).copy()

    for i, feat in enumerate(KBEST_FEATURES):
        if feat in missing or X[feat].isna().all():
            X[feat] = scaler.mean_[i]

    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(0, inplace=True)

    X_scaled = scaler.transform(X)
    numeric_preds = model.predict(X_scaled)
    decoded_preds = le.inverse_transform(numeric_preds)

    try:
        proba = model.predict_proba(X_scaled)
        confidence = proba.max(axis=1)
    except AttributeError:
        confidence = np.ones(len(decoded_preds))

    threshold = Config.CONFIDENCE_THRESHOLD
    rows = []
    for i, (pred, conf) in enumerate(zip(decoded_preds, confidence)):
        pred_str = str(pred)
        is_attack = pred_str.upper() != "BENIGN"

        if is_attack and conf >= threshold:
            alert_level = "high"
        elif is_attack and conf >= 0.5:
            alert_level = "medium"
        else:
            alert_level = "low"

        row = {
            "id": i + 1,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prediction": pred_str,
            "confidence": round(float(conf), 4),
            "alert_level": alert_level,
            "src_ip": _get_meta(meta, 'src_ip', 'Src IP', idx=i, default="unknown"),
            "dst_ip": _get_meta(meta, 'dst_ip', 'Dst IP', idx=i, default="unknown"),
            "dst_port": int(df['Dst Port'].iloc[i]) if 'Dst Port' in df.columns else 0,
            "protocol": _proto_name(df['Protocol'].iloc[i]) if 'Protocol' in df.columns else "?",
            "timespan": _get_meta(meta, 'timespan', 'Timestamp', idx=i, default=""),
        }
        rows.append(row)

    return rows


def get_feature_importance() -> list[dict]:
    if model is None:
        return []
    importance = model.feature_importances_
    pairs = sorted(
        zip(KBEST_FEATURES, importance.tolist()),
        key=lambda x: -x[1]
    )
    return [{"feature": f, "importance": round(v, 4)} for f, v in pairs[:20]]


def _get_meta(meta, *keys, idx, default):
    for k in keys:
        if k in meta:
            try:
                return str(meta[k].iloc[idx])
            except Exception:
                pass
    return default


def _proto_name(v):
    try:
        v = int(v)
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(v, f"Other({v})")
    except Exception:
        return str(v)


def _write_log(rows: list[dict]):
    log_dir = os.path.dirname(Config.LOG_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    with open(Config.LOG_PATH, "a") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def _build_counts(rows: list[dict]) -> dict:
    counts = {}
    for r in rows:
        p = r["prediction"]
        counts[p] = counts.get(p, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def run_static_prediction(filepath: str = None) -> tuple[list, dict]:
    global _latest_rows, _latest_counts
    path = filepath or Config.DATA_PATH

    if not os.path.exists(path):
        raise FileNotFoundError(f"Data file not found: {path}")

    logger.info(f"Static mode — loading {path}")
    df = _safe_read_csv(path)
    rows = predict_dataframe(df)

    with _live_lock:
        _latest_rows = rows
        _latest_counts = _build_counts(rows)

    _write_log(rows)
    attacks = sum(1 for r in rows if r['alert_level'] in ('high', 'medium'))
    logger.info(f"Done — {len(rows)} rows, {attacks} attacks")
    print(f"[ML] Static: {len(rows)} rows, {attacks} attacks detected")
    return rows, _latest_counts



_injector_thread = None

def _generate_synthetic_benign(columns: list, count: int) -> pd.DataFrame:
    import random
    rows = []
    for _ in range(count):
        row = {}
        for col in columns:
            cl = col.lower().strip()
            if cl == 'dst port':
                row[col] = random.choice([80, 443, 443, 443, 8080, 53])
            elif cl == 'protocol':
                row[col] = random.choice([6, 6, 6, 17])
            elif 'packet length' in cl and ('max' in cl or 'mean' in cl):
                row[col] = round(random.uniform(40, 1460), 2)
            elif 'packet length' in cl and 'min' in cl:
                row[col] = round(random.uniform(0, 40), 2)
            elif 'packet length' in cl and ('std' in cl or 'variance' in cl):
                row[col] = round(random.uniform(0, 500), 2)
            elif 'average packet size' in cl:
                row[col] = round(random.uniform(100, 800), 2)
            elif 'iat' in cl:
                row[col] = round(random.uniform(1000, 500000), 2)
            elif 'packets/s' in cl:
                row[col] = round(random.uniform(1, 100), 2)
            elif 'fin flag' in cl:
                row[col] = random.choice([0, 1])
            elif 'syn flag' in cl:
                row[col] = 1
            elif 'rst flag' in cl:
                row[col] = 0
            elif 'down/up ratio' in cl:
                row[col] = round(random.uniform(0.5, 2.0), 2)
            elif 'bulk rate' in cl:
                row[col] = 0.0
            elif 'subflow' in cl and 'packet' in cl:
                row[col] = random.randint(1, 20)
            elif 'subflow' in cl and 'byte' in cl:
                row[col] = random.randint(100, 5000)
            elif 'init win' in cl:
                row[col] = random.choice([8192, 16384, 29200, 65535])
            elif 'seg size min' in cl:
                row[col] = random.choice([20, 32, 40])
            elif 'active' in cl or 'idle' in cl:
                row[col] = round(random.uniform(0, 100000), 2)
            elif cl in ('src ip', 'src_ip'):
                row[col] = f"192.168.1.{random.randint(2, 254)}"
            elif cl in ('dst ip', 'dst_ip'):
                row[col] = random.choice(["142.250.80.46", "104.244.42.65", "157.240.1.35"])
            elif cl == 'timestamp' or cl == 'timespan':
                row[col] = datetime.now().strftime("%d/%m/%Y %I:%M:%S %p")
            elif 'label' in cl:
                row[col] = "BENIGN"
            else:
                row[col] = round(random.uniform(0, 100), 2)
        rows.append(row)
    return pd.DataFrame(rows, columns=columns)


def _run_injector_background():
    import random

    BENIGN_LABELS = {'benign', 'normal', 'background', 'legitimate'}

    logger.info("Attack injector started in background")
    print("[INJECTOR] Background injector started — feeding mixed traffic into live_capture.csv")

    try:
        source_df = _safe_read_csv(Config.DATA_PATH)
        if source_df.empty:
            logger.error("Injector: source dataset is empty")
            return
        source_df.columns = source_df.columns.str.strip()

        # Find label column
        label_col = None
        for col in source_df.columns:
            if col.strip().lower() == 'label':
                label_col = col
                break

        if label_col:
            attacks = source_df[~source_df[label_col].str.strip().str.lower().isin(BENIGN_LABELS)]
            benign  = source_df[source_df[label_col].str.strip().str.lower().isin(BENIGN_LABELS)]
        else:
            attacks = source_df
            benign  = pd.DataFrame()

        if len(benign) == 0:
            logger.warning("Injector: zero benign rows in dataset — generating synthetic benign traffic")
            print("[INJECTOR] ⚠ No BENIGN in dataset — generating synthetic normal traffic")
            benign = _generate_synthetic_benign(source_df.columns.tolist(), 200)
            print(f"[INJECTOR] Synthetic benign pool: {len(benign)} rows ✓")

        print(f"[INJECTOR] Attack pool: {len(attacks)}, Benign pool: {len(benign)}")

        live_path = Config.LIVE_CSV
    except Exception as e:
        logger.error(f"Injector init failed: {e}")
        return

    while _live_running:
        try:
            n = random.randint(3, 5)
            n_benign = max(1, int(n * 0.3))
            n_attacks = n - n_benign

            samples = []
            if len(attacks) > 0 and n_attacks > 0:
                samples.append(attacks.sample(n=min(n_attacks, len(attacks)), replace=True))
            if len(benign) > 0 and n_benign > 0:
                samples.append(benign.sample(n=min(n_benign, len(benign)), replace=True))

            if not samples:
                time.sleep(5)
                continue

            batch = pd.concat(samples, ignore_index=True)

            prefixes = [(45, 33), (185, 220), (91, 134), (23, 94), (104, 18),
                        (198, 51), (203, 0), (85, 25), (77, 88)]
            for i in range(len(batch)):
                is_benign = False
                if label_col and label_col in batch.columns:
                    is_benign = str(batch.at[i, label_col]).strip().lower() in BENIGN_LABELS

                for col in ['Src IP', 'src_ip']:
                    if col in batch.columns:
                        if is_benign:
                            batch.at[i, col] = f"192.168.1.{random.randint(2, 254)}"
                        else:
                            p = random.choice(prefixes)
                            batch.at[i, col] = f"{p[0]}.{p[1]}.{random.randint(1,254)}.{random.randint(1,254)}"

            now = datetime.now().strftime("%d/%m/%Y %I:%M:%S %p")
            for col in ['Timestamp', 'timespan']:
                if col in batch.columns:
                    batch[col] = now

            batch = batch.sample(frac=1).reset_index(drop=True)

            write_header = not os.path.exists(live_path) or os.path.getsize(live_path) == 0
            batch.to_csv(live_path, mode='a', header=write_header, index=False)

            if label_col and label_col in batch.columns:
                b_count = batch[label_col].str.strip().str.lower().isin(BENIGN_LABELS).sum()
                a_count = len(batch) - b_count
                atk_types = batch[~batch[label_col].str.strip().str.lower().isin(BENIGN_LABELS)][label_col].value_counts()
                type_str = ', '.join(f"{k}({v})" for k, v in atk_types.items())
                print(f"[INJECTOR] +{len(batch)} rows ({a_count} attack, {b_count} benign) [{type_str}]")
            else:
                print(f"[INJECTOR] +{len(batch)} rows")

            logger.info(f"Injector: +{len(batch)} rows")

        except Exception as e:
            logger.error(f"Injector error: {e}")

        time.sleep(random.randint(5, 10))

    logger.info("Attack injector stopped")
    print("[INJECTOR] Background injector stopped")


def _extract_features_from_pcap(pcap_path: str) -> pd.DataFrame:

    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        logger.error("scapy not installed — cannot extract features from pcap")
        return pd.DataFrame()

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error(f"Failed to read pcap: {e}")
        return pd.DataFrame()

    if not packets:
        return pd.DataFrame()

    flows = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto

        sport = dport = 0
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        fwd_key = (src, dst, sport, dport, proto)
        rev_key = (dst, src, dport, sport, proto)

        if fwd_key in flows:
            flows[fwd_key].append(('fwd', pkt))
        elif rev_key in flows:
            flows[rev_key].append(('bwd', pkt))
        else:
            flows[fwd_key] = [('fwd', pkt)]

    if not flows:
        return pd.DataFrame()

    import statistics
    all_flow_features = []

    for flow_key, pkt_list in flows.items():
        if len(pkt_list) < 2:
            continue  

        src_ip, dst_ip, sport, dport, proto = flow_key

        fwd_pkts = [p for d, p in pkt_list if d == 'fwd']
        bwd_pkts = [p for d, p in pkt_list if d == 'bwd']

        fwd_lengths = [len(p) for p in fwd_pkts] or [0]
        bwd_lengths = [len(p) for p in bwd_pkts] or [0]
        all_lengths = fwd_lengths + bwd_lengths

        all_times = sorted([float(p.time) for _, p in pkt_list])
        fwd_times = sorted([float(p.time) for p in fwd_pkts]) if fwd_pkts else []
        bwd_times = sorted([float(p.time) for p in bwd_pkts]) if bwd_pkts else []

        def iat(times):
            if len(times) < 2:
                return [0]
            return [times[i+1] - times[i] for i in range(len(times)-1)]

        fwd_iat = iat(fwd_times)
        bwd_iat = iat(bwd_times)

        def safe_std(vals):
            if len(vals) < 2:
                return 0.0
            try:
                return statistics.stdev(vals)
            except Exception:
                return 0.0

        def safe_mean(vals):
            return statistics.mean(vals) if vals else 0.0

        duration = max(all_times) - min(all_times) if len(all_times) > 1 else 0.001

        fin_count = syn_count = rst_count = 0
        for _, p in pkt_list:
            if p.haslayer(TCP):
                flags = p[TCP].flags
                if flags & 0x01: fin_count += 1
                if flags & 0x02: syn_count += 1
                if flags & 0x04: rst_count += 1

        flow = {
            'Dst Port': dport,
            'Protocol': proto,
            'Fwd Packet Length Min': min(fwd_lengths),
            'Bwd Packet Length Max': max(bwd_lengths),
            'Bwd Packet Length Min': min(bwd_lengths),
            'Bwd Packet Length Mean': safe_mean(bwd_lengths),
            'Bwd Packet Length Std': safe_std(bwd_lengths),
            'Fwd IAT Std': safe_std(fwd_iat) * 1e6,
            'Bwd IAT Std': safe_std(bwd_iat) * 1e6,
            'Bwd IAT Max': max(bwd_iat) * 1e6 if bwd_iat else 0,
            'Bwd Packets/s': len(bwd_pkts) / duration if duration > 0 else 0,
            'Packet Length Min': min(all_lengths),
            'Packet Length Max': max(all_lengths),
            'Packet Length Mean': safe_mean(all_lengths),
            'Packet Length Std': safe_std(all_lengths),
            'Packet Length Variance': safe_std(all_lengths) ** 2,
            'FIN Flag Count': fin_count,
            'SYN Flag Count': syn_count,
            'RST Flag Count': rst_count,
            'Down/Up Ratio': len(bwd_pkts) / max(len(fwd_pkts), 1),
            'Average Packet Size': safe_mean(all_lengths),
            'Bwd Segment Size Avg': safe_mean(bwd_lengths),
            'Bwd Bulk Rate Avg': sum(bwd_lengths) / duration if duration > 0 else 0,
            'Subflow Fwd Packets': len(fwd_pkts),
            'Subflow Bwd Bytes': sum(bwd_lengths),
            'FWD Init Win Bytes': fwd_pkts[0][TCP].window if fwd_pkts and fwd_pkts[0].haslayer(TCP) else 0,
            'Fwd Seg Size Min': min(fwd_lengths) if fwd_lengths else 0,
            'Active Mean': duration * 1e6 * 0.5,
            'Active Min': duration * 1e6 * 0.3,
            'Idle Std': 0.0,
            # Metadata
            'Src IP': src_ip,
            'Dst IP': dst_ip,
            'Timestamp': datetime.now().strftime("%d/%m/%Y %I:%M:%S %p"),
        }
        all_flow_features.append(flow)

    if not all_flow_features:
        return pd.DataFrame()

    df = pd.DataFrame(all_flow_features)
    logger.info(f"Extracted {len(df)} flows from pcap ({pcap_path})")
    return df


def run_live_prediction():
   
    global _live_running, _latest_rows, _latest_counts, _injector_thread
    global _live_csv_last_pos, _live_csv_header
    _live_running = True
    _live_csv_last_pos = 0
    _live_csv_header = None
    os.makedirs(Config.FLOWS_DIR, exist_ok=True)
    logger.info(f"Live mode started — CICFlowMeter + injector")

    _injector_thread = threading.Thread(target=_run_injector_background, daemon=True)
    _injector_thread.start()

    tshark_path = None
    for path in [
        "tshark",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
    ]:
        try:
            subprocess.run([path, "--version"], capture_output=True, timeout=5)
            tshark_path = path
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if tshark_path:
        logger.info(f"tshark detected — capturing real traffic on interface {Config.NETWORK_INTERFACE}")
        print(f"[ML] tshark found: {tshark_path}")
        print(f"[ML] Real traffic capture enabled on interface: {Config.NETWORK_INTERFACE}")
    else:
        logger.info("No tshark found — using attack injector only")
        print("[ML] No tshark/Wireshark — using attack injector only")

    while _live_running:
        all_rows = []

        if tshark_path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = os.path.join(Config.FLOWS_DIR, f"capture_{ts}.pcap")

            try:
                capture_secs = min(Config.CAPTURE_SECS, 15)
                subprocess.run(
                    [tshark_path, "-i", Config.NETWORK_INTERFACE, "-w", pcap_file,
                     "-a", f"duration:{capture_secs}"],
                    capture_output=True, text=True,
                    timeout=capture_secs + 10,
                )
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                logger.error(f"tshark capture error: {e}")
                print(f"[ML] tshark error: {e}")

            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 100:
                try:
                    df = _extract_features_from_pcap(pcap_file)
                    if df is not None and not df.empty:
                        rows = predict_dataframe(df)
                        all_rows.extend(rows)
                        benign_count = sum(1 for r in rows if r['alert_level'] == 'low')
                        attack_count = len(rows) - benign_count
                        logger.info(f"Real traffic: {len(rows)} flows ({attack_count} attacks, {benign_count} benign)")
                        print(f"[ML] Real traffic: +{len(rows)} flows ({attack_count} attacks, {benign_count} benign)")
                except Exception as e:
                    logger.error(f"Feature extraction error: {e}")
                    print(f"[ML] Feature extraction error: {e}")

            try:
                if os.path.exists(pcap_file):
                    os.remove(pcap_file)
            except Exception:
                pass

        live_path = Config.LIVE_CSV
        try:
            if os.path.exists(live_path):
                file_size = os.path.getsize(live_path)
                if file_size > _live_csv_last_pos:
                    with open(live_path, 'r', encoding='utf-8') as f:
                        if _live_csv_header is None:
                            _live_csv_header = f.readline().strip()
                            _live_csv_last_pos = f.tell()
                        else:
                            f.seek(_live_csv_last_pos)
                            new_lines = f.readlines()
                            _live_csv_last_pos = f.tell()

                            if new_lines:
                                import io
                                csv_text = _live_csv_header + '\n' + ''.join(new_lines)
                                df = pd.read_csv(io.StringIO(csv_text))
                                if not df.empty:
                                    rows = predict_dataframe(df)
                                    all_rows.extend(rows)
                                    attacks = sum(1 for r in rows if r['alert_level'] in ('high', 'medium'))
                                    logger.info(f"Injector batch: {len(rows)} flows, {attacks} attacks")
        except Exception as e:
            logger.error(f"Live CSV read error: {e}")

        if all_rows:
            with _live_lock:
                _latest_rows = (all_rows + _latest_rows)[:5000]
                _latest_counts = _build_counts(_latest_rows)
            _write_log(all_rows)
            print(f"[ML] Live: +{len(all_rows)} rows processed")
            yield all_rows

        _cleanup_flows()
        time.sleep(3)

    logger.info("Live pipeline stopped")


def stop_live():
    global _live_running
    _live_running = False


def is_live_running() -> bool:
    return _live_running


def get_latest_results() -> tuple[list, dict]:
    with _live_lock:
        return list(_latest_rows), dict(_latest_counts)


def _cleanup_flows():
    try:
        files = sorted(
            [os.path.join(Config.FLOWS_DIR, f)
             for f in os.listdir(Config.FLOWS_DIR) if f.endswith(".csv")],
            key=os.path.getmtime,
        )
        for f in files[:-10]:
            os.remove(f)
    except Exception:
        pass



def _safe_read_csv(path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(path)
    except pd.errors.ParserError:
        pass
    try:
        return pd.read_csv(path, engine="python", on_bad_lines="skip")
    except Exception:
        pass
    import csv
    import io
    rows = []
    try:
        with open(path, encoding="utf-8", newline="") as f:
            r = csv.reader(f)
            header = next(r, None)
            if header:
                rows.append(header)
                for rec in r:
                    if len(rec) == len(header):
                        rows.append(rec)
    except Exception:
        return pd.DataFrame()
    if not rows:
        return pd.DataFrame()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    for rec in rows:
        w.writerow(rec)
    buf.seek(0)
    try:
        return pd.read_csv(buf)
    except Exception:
        return pd.DataFrame()


_live_csv_last_pos = 0    
_live_csv_header = None   

def run_live_csv_prediction():
  
    global _live_running, _latest_rows, _latest_counts
    global _live_csv_last_pos, _live_csv_header
    _live_running = True
    _live_csv_last_pos = 0
    _live_csv_header = None

    live_path = Config.LIVE_CSV
    logger.info(f"Live-CSV mode started — watching {live_path}")
    print(f"[ML] Live-CSV mode — watching {live_path}")

    while _live_running:
        try:
            if not os.path.exists(live_path):
                time.sleep(2)
                continue

            file_size = os.path.getsize(live_path)
            if file_size <= _live_csv_last_pos:
                time.sleep(2)
                continue

            with open(live_path, 'r', encoding='utf-8') as f:
                if _live_csv_header is None:
                    _live_csv_header = f.readline().strip()
                    _live_csv_last_pos = f.tell()
                    continue

                f.seek(_live_csv_last_pos)
                new_lines = f.readlines()
                _live_csv_last_pos = f.tell()

            if not new_lines:
                time.sleep(2)
                continue

            import io
            csv_text = _live_csv_header + '\n' + ''.join(new_lines)
            df = pd.read_csv(io.StringIO(csv_text))

            if df.empty:
                time.sleep(2)
                continue

            rows = predict_dataframe(df)

            with _live_lock:
                _latest_rows = (rows + _latest_rows)[:5000]
                _latest_counts = _build_counts(_latest_rows)

            _write_log(rows)
            attacks = sum(1 for r in rows if r['alert_level'] in ('high', 'medium'))
            logger.info(f"Live-CSV batch: {len(rows)} flows, {attacks} attacks")
            print(f"[ML] Live-CSV: +{len(rows)} rows ({attacks} attacks)")

            yield rows

        except Exception as e:
            logger.error(f"Live-CSV error: {e}")
            time.sleep(3)
            continue

        time.sleep(2)

    logger.info("Live-CSV pipeline stopped")


def reset_live_csv_reader():
    """Reset the incremental reader position (e.g., when switching modes)."""
    global _live_csv_last_pos, _live_csv_header
    _live_csv_last_pos = 0
    _live_csv_header = None


if __name__ == "__main__":
    rows, counts = run_static_prediction()
    print(f"\nPrediction counts ({len(rows)} total):")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    print(f"\nFeature importance (top 10):")
    for fi in get_feature_importance()[:10]:
        print(f"  {fi['feature']}: {fi['importance']}")
