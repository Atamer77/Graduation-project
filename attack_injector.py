

import pandas as pd
import numpy as np
import os
import sys
import time
import random
import argparse
from datetime import datetime



SOURCE_CSV   = os.getenv("DATA_PATH", "Artifacts/merged_test_data.csv")
LIVE_CSV     = os.getenv("LIVE_CSV", "live_capture.csv")
BENIGN_RATIO = 0.3   


def load_attack_pool(path: str) -> pd.DataFrame:
    """Load the dataset and separate attack vs benign rows."""
    if not os.path.exists(path):
        print(f"[INJECTOR] ERROR: Source CSV not found: {path}")
        sys.exit(1)

    df = pd.read_csv(path)
    df.columns = df.columns.str.strip()
    print(f"[INJECTOR] Loaded {len(df)} rows from {path}")

   
    label_col = None
    for col in ['Label', 'label', 'LABEL']:
        if col in df.columns:
            label_col = col
            break

    if label_col:
        attacks = df[df[label_col].str.upper() != 'BENIGN']
        benign  = df[df[label_col].str.upper() == 'BENIGN']
        print(f"[INJECTOR] Attack pool: {len(attacks)} rows, Benign pool: {len(benign)} rows")
    else:
   
        attacks = df
        benign  = pd.DataFrame()
        print(f"[INJECTOR] No Label column found — using all {len(df)} rows as pool")

    return attacks, benign


def randomize_ip() -> str:
    """Generate a random public-looking IP for demo purposes."""
    
    prefixes = [
        (45, 33), (185, 220), (91, 134), (23, 94), (104, 18),
        (198, 51), (203, 0), (85, 25), (77, 88), (62, 210),
    ]
    a, b = random.choice(prefixes)
    c = random.randint(1, 254)
    d = random.randint(1, 254)
    return f"{a}.{b}.{c}.{d}"


def inject_batch(attacks: pd.DataFrame, benign: pd.DataFrame,
                 count: int, live_csv: str):
    """Sample attack rows, randomize IPs, append to live CSV."""
    n_attacks = max(1, int(count * (1 - BENIGN_RATIO)))
    n_benign  = count - n_attacks

    samples = []

    if len(attacks) > 0:
        attack_sample = attacks.sample(n=min(n_attacks, len(attacks)), replace=True)
        samples.append(attack_sample)

    if len(benign) > 0 and n_benign > 0:
        benign_sample = benign.sample(n=min(n_benign, len(benign)), replace=True)
        samples.append(benign_sample)

    if not samples:
        print("[INJECTOR] No rows to inject")
        return

    batch = pd.concat(samples, ignore_index=True)

    if 'Src IP' in batch.columns:
        batch['Src IP'] = [randomize_ip() for _ in range(len(batch))]
    if 'src_ip' in batch.columns:
        batch['src_ip'] = [randomize_ip() for _ in range(len(batch))]

    now = datetime.now().strftime("%d/%m/%Y %I:%M:%S %p")
    if 'Timestamp' in batch.columns:
        batch['Timestamp'] = now
    if 'timespan' in batch.columns:
        batch['timespan'] = now

    write_header = not os.path.exists(live_csv) or os.path.getsize(live_csv) == 0
    batch.to_csv(live_csv, mode='a', header=write_header, index=False)

    if 'Label' in batch.columns:
        attack_types = batch[batch['Label'].str.upper() != 'BENIGN']['Label'].value_counts()
        type_str = ', '.join(f"{k}({v})" for k, v in attack_types.items())
    else:
        type_str = f"{len(batch)} rows"

    print(f"[INJECTOR] {datetime.now().strftime('%H:%M:%S')} — "
          f"Injected {len(batch)} rows → {live_csv}  [{type_str}]")


def main():
    parser = argparse.ArgumentParser(description="Smart Alert Attack Injector")
    parser.add_argument("--count", type=int, default=3,
                        help="Number of rows to inject per cycle (default: 3)")
    parser.add_argument("--interval", type=int, default=8,
                        help="Seconds between injections (default: 8)")
    parser.add_argument("--source", type=str, default=SOURCE_CSV,
                        help="Source CSV with attack samples")
    parser.add_argument("--output", type=str, default=LIVE_CSV,
                        help="Output live CSV path (default: live_capture.csv)")
    parser.add_argument("--once", action="store_true",
                        help="Inject once and exit (no loop)")
    parser.add_argument("--reset", action="store_true",
                        help="Delete existing live_capture.csv before starting")
    args = parser.parse_args()

    print("=" * 55)
    print("  Smart Alert — Attack Injector (Demo Tool)")
    print(f"  Source:   {args.source}")
    print(f"  Output:   {args.output}")
    print(f"  Count:    {args.count} rows/cycle")
    print(f"  Interval: {args.interval}s")
    print("=" * 55)

    if args.reset and os.path.exists(args.output):
        os.remove(args.output)
        print(f"[INJECTOR] Deleted existing {args.output}")

    attacks, benign = load_attack_pool(args.source)

    if args.once:
        inject_batch(attacks, benign, args.count, args.output)
        return

    print(f"\n[INJECTOR] Running — Ctrl+C to stop\n")
    try:
        while True:
            inject_batch(attacks, benign, args.count, args.output)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[INJECTOR] Stopped.")


if __name__ == "__main__":
    main()
