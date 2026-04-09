#!/usr/bin/env python3
"""
training/train_all.py
Train Courra-Sec ML models on existing log data from the database.

Run from the project root:
    python training/train_all.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("BLOCK_FORTRESS_URL", "http://localhost:5000")
os.environ.setdefault("SECRET_KEY", "training-mode")

import json
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from app.main import app
from app.models import LogEntry, Attack
from app.ml import UEBAEngine, SKLEARN_AVAILABLE, MODEL_DIR

MODEL_DIR.mkdir(parents=True, exist_ok=True)

SEV_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

HIGH_RISK_TYPES = {"sql", "rce", "command", "xxe", "ssrf", "lfi", "rfi", "injection"}
MED_RISK_TYPES  = {"brute", "xss", "csrf", "traversal", "admin", "privilege"}


def featurize(log) -> list:
    sev     = SEV_MAP.get((log.severity or "medium").lower(), 2)
    payload = min(len(str(log.payload or "")), 5000)
    hour    = log.timestamp.hour if log.timestamp else 0
    at      = (log.attack_type or "").lower()
    at_risk = 3 if any(k in at for k in HIGH_RISK_TYPES) else \
              2 if any(k in at for k in MED_RISK_TYPES)  else 1
    ep      = (log.endpoint or "").lower()
    ep_risk = 1 if any(k in ep for k in ["/admin", "/manage", "/login", "/api"]) else 0
    return [sev, payload, hour, at_risk, ep_risk]


def train_anomaly_detector(logs: list) -> bool:
    print(f"\n[1/2] Anomaly Detector")
    print(f"      Training on {len(logs)} log entries...")

    if not SKLEARN_AVAILABLE:
        print("      scikit-learn not available -- skipping (statistical fallback will be used)")
        return False

    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib

    X = np.array([featurize(l) for l in logs])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Estimate contamination from known attack types in the data
    n_malicious = sum(
        1 for l in logs
        if l.severity in ("critical", "high") or
           any(k in (l.attack_type or "").lower() for k in HIGH_RISK_TYPES | MED_RISK_TYPES)
    )
    contamination = max(0.05, min(0.4, n_malicious / len(logs)))

    model = IsolationForest(
        contamination=contamination,
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    predictions  = model.predict(X_scaled)
    n_anomalies  = int((predictions == -1).sum())
    anomaly_rate = n_anomalies / len(logs) * 100

    out_path = MODEL_DIR / "anomaly_detector.joblib"
    # compress=3 reduces file size ~60% with minimal load-time overhead;
    # also avoids antivirus slowdowns on Windows with large uncompressed files.
    joblib.dump({"model": model, "scaler": scaler}, out_path, compress=3)

    print(f"      Contamination used : {contamination:.2%}")
    print(f"      Anomalies flagged  : {n_anomalies}/{len(logs)} ({anomaly_rate:.1f}%)")
    print(f"      Saved to           : {out_path}")
    return True


def build_ueba_profiles(logs: list) -> int:
    print(f"\n[2/2] UEBA Profiles")
    print(f"      Building from {len(logs)} log entries...")

    ueba = UEBAEngine()
    for log in logs:
        log_dict = {
            "source_ip":   log.ip_address,
            "ip_address":  log.ip_address,
            "attack_type": log.attack_type or "unknown",
            "event_type":  log.attack_type or "unknown",
            "endpoint":    log.endpoint or "unknown",
            "path":        log.endpoint or "unknown",
            "severity":    log.severity or "medium",
            "payload":     log.payload or "",
        }
        ueba.update(log_dict)

    profiles_data = {}
    for entity_id, p in ueba._profiles.items():
        profiles_data[entity_id] = {
            "total_events":    p["total_events"],
            "attack_types":    dict(p["attack_types"]),
            "known_countries": list(p["known_countries"]),
            "last_seen":       p["last_seen"],
            "first_seen":      p["first_seen"],
            "hourly_baseline": {str(k): v for k, v in p["hourly_baseline"].items()},
        }

    out_path = MODEL_DIR / "ueba_profiles.json"
    with open(out_path, "w") as f:
        json.dump(profiles_data, f, indent=2)

    n = len(profiles_data)
    print(f"      Entities profiled  : {n}")
    print(f"      Saved to           : {out_path}")
    return n


def main():
    print("=" * 50)
    print("Courra-Sec ML Training")
    print("=" * 50)

    with app.app_context():
        logs = LogEntry.query.order_by(LogEntry.timestamp.asc()).all()

        if not logs:
            print("No log data found in the database. Ingest some logs first.")
            sys.exit(0)

        print(f"Database: {len(logs)} log entries found")

        # Summarise the data
        severities   = defaultdict(int)
        attack_types = defaultdict(int)
        for l in logs:
            severities[(l.severity or "unknown")] += 1
            attack_types[(l.attack_type or "unknown")] += 1

        print("\nSeverity breakdown:")
        for sev, cnt in sorted(severities.items(), key=lambda x: -x[1]):
            print(f"  {sev:<12} {cnt}")
        print("\nTop attack types:")
        for at, cnt in sorted(attack_types.items(), key=lambda x: -x[1])[:8]:
            print(f"  {at:<40} {cnt}")

        # Train
        anomaly_ok = train_anomaly_detector(logs)
        n_profiles = build_ueba_profiles(logs)

        # Metadata
        meta = {
            "trained_at":     datetime.utcnow().isoformat(),
            "total_logs":     len(logs),
            "ueba_entities":  n_profiles,
            "anomaly_model":  "IsolationForest" if anomaly_ok else "statistical_fallback",
            "sklearn":        SKLEARN_AVAILABLE,
        }
        meta_path = MODEL_DIR / "training_meta.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        print(f"\n{'=' * 50}")
        print(f"Training complete")
        print(f"  Models saved to : {MODEL_DIR}")
        print(f"  Trained at      : {meta['trained_at']}")
        print(f"  Restart Courra-Sec to load the trained models.")
        print(f"{'=' * 50}")


if __name__ == "__main__":
    main()
