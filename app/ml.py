"""
app/ml.py — Courra-Sec ML Pipeline
Provides: anomaly detection (IsolationForest / statistical fallback),
UEBA, risk scoring, entity graph, attack-chain detection, MITRE mapping.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import json
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "models"

# scikit-learn is optional — statistical fallback used when unavailable
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not installed -- using statistical anomaly detection fallback")


# ──────────────────────────────────────────────────────────────
# MITRE ATT&CK mapping  (attack_type keyword → tactic)
# ──────────────────────────────────────────────────────────────
MITRE_MAP: dict[str, str] = {
    "bruteforce":              "TA0006 Credential Access",
    "brute_force":             "TA0006 Credential Access",
    "brute force":             "TA0006 Credential Access",
    "sql injection":           "TA0001 Initial Access",
    "sqli":                    "TA0001 Initial Access",
    "xss":                     "TA0001 Initial Access",
    "os_command_injection":    "TA0002 Execution",
    "command injection":       "TA0002 Execution",
    "geo_velocity":            "TA0001 Initial Access",
    "admin_privilege_attempt": "TA0004 Privilege Escalation",
    "privilege escalation":    "TA0004 Privilege Escalation",
    "multiple_attack_types":   "TA0040 Impact",
    "blocked_ip_detected":     "TA0001 Initial Access",
    "path traversal":          "TA0007 Discovery",
    "directory traversal":     "TA0007 Discovery",
    "csrf":                    "TA0001 Initial Access",
    "rce":                     "TA0002 Execution",
    "lfi":                     "TA0007 Discovery",
    "rfi":                     "TA0001 Initial Access",
    "xxe":                     "TA0001 Initial Access",
    "ssrf":                    "TA0007 Discovery",
}

# Known multi-step attack chain patterns (ordered subsets)
CHAIN_PATTERNS: list[dict] = [
    {"pattern_name": "Recon to Exploit",             "pattern": ["path traversal", "sql injection", "rce"],           "chain_risk": 0.90},
    {"pattern_name": "Credential Theft to Escalation","pattern": ["bruteforce", "admin_privilege_attempt"],            "chain_risk": 0.85},
    {"pattern_name": "Injection to Command Execution","pattern": ["sql injection", "os_command_injection"],            "chain_risk": 0.95},
    {"pattern_name": "Multi-Vector Attack",           "pattern": ["xss", "csrf", "sql injection"],                    "chain_risk": 0.80},
    {"pattern_name": "Scanning to Brute Force",       "pattern": ["path traversal", "bruteforce"],                    "chain_risk": 0.75},
]


# ──────────────────────────────────────────────────────────────
# UEBA — User & Entity Behaviour Analytics
# ──────────────────────────────────────────────────────────────
class UEBAEngine:
    def __init__(self) -> None:
        self._profiles: dict = defaultdict(lambda: {
            "total_events":     0,
            "attack_types":     defaultdict(int),
            "endpoints":        defaultdict(int),
            "known_countries":  set(),
            "last_seen":        None,
            "first_seen":       None,
            "hourly_baseline":  defaultdict(int),
        })
        self._anomaly_history: dict[str, list[str]] = defaultdict(list)

    def update(self, log_dict: dict) -> list[str]:
        """Update profile for the entity and return any UEBA anomalies detected."""
        entity_id = log_dict.get("source_ip") or log_dict.get("ip_address", "unknown")
        now       = datetime.utcnow()
        p         = self._profiles[entity_id]

        p["total_events"] += 1
        p["last_seen"]     = now.isoformat()
        if not p["first_seen"]:
            p["first_seen"] = now.isoformat()

        at = (log_dict.get("attack_type") or log_dict.get("event_type") or "unknown").lower()
        ep = log_dict.get("endpoint") or log_dict.get("path") or "unknown"
        p["attack_types"][at] += 1
        p["endpoints"][ep]    += 1

        hour = now.hour
        p["hourly_baseline"][hour] += 1

        country = log_dict.get("country")
        if country:
            p["known_countries"].add(country)

        anomalies: list[str] = []

        # 1. Activity spike — current hour > 3× average
        counts = list(p["hourly_baseline"].values())
        if len(counts) > 1:
            avg = sum(counts) / len(counts)
            if avg > 0 and p["hourly_baseline"][hour] > avg * 3:
                anomalies.append(
                    f"Unusual spike at {hour:02d}:00 "
                    f"({p['hourly_baseline'][hour]} events vs avg {avg:.1f})"
                )

        # 2. First-time attack type (after warm-up of 5 events)
        if p["total_events"] > 5 and p["attack_types"][at] == 1:
            anomalies.append(f"New attack type observed: {at}")

        # 3. High endpoint diversity — likely scanning
        if len(p["endpoints"]) > 10 and p["endpoints"][ep] == 1:
            anomalies.append(
                f"Scanning behaviour detected "
                f"({len(p['endpoints'])} unique endpoints probed)"
            )

        self._anomaly_history[entity_id].extend(anomalies)
        return anomalies

    def load_profiles(self, path: str) -> bool:
        """Restore UEBA profiles saved by the training script."""
        try:
            with open(path) as f:
                data = json.load(f)
            for entity_id, p in data.items():
                prof = self._profiles[entity_id]
                prof["total_events"]    = p.get("total_events", 0)
                prof["attack_types"]    = defaultdict(int, p.get("attack_types", {}))
                prof["known_countries"] = set(p.get("known_countries", []))
                prof["last_seen"]       = p.get("last_seen")
                prof["first_seen"]      = p.get("first_seen")
                prof["hourly_baseline"] = defaultdict(int, {int(k): v for k, v in p.get("hourly_baseline", {}).items()})
            return True
        except Exception as e:
            print(f"UEBAEngine load_profiles error: {e}")
            return False

    def get_profile(self, entity_id: str) -> dict:
        p = self._profiles.get(entity_id)
        if not p:
            return {}
        return {
            "entity_id":       entity_id,
            "total_events":    p["total_events"],
            "attack_types":    dict(p["attack_types"]),
            "known_countries": list(p["known_countries"]),
            "last_seen":       p["last_seen"],
            "first_seen":      p["first_seen"],
            "top_endpoints":   sorted(p["endpoints"].items(), key=lambda x: -x[1])[:5],
        }


# ──────────────────────────────────────────────────────────────
# Risk Scorer
# ──────────────────────────────────────────────────────────────
class RiskScorer:
    def __init__(self) -> None:
        self._history: dict[str, list[dict]] = defaultdict(list)

    def score(self, log_dict: dict, ueba_anomalies: list, is_anomaly: bool) -> dict:
        """Return signal breakdown and 0–100 composite risk score."""
        sev = (log_dict.get("severity") or "medium").lower()
        at  = (log_dict.get("attack_type") or log_dict.get("event_type") or "").lower()

        sev_score = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 5}.get(sev, 15)

        high_risk = {"sql injection", "sqli", "os_command_injection", "command injection",
                     "rce", "lfi", "rfi", "xxe", "ssrf"}
        med_risk  = {"bruteforce", "brute_force", "xss", "csrf", "path traversal"}
        inherent  = 30 if any(t in at for t in high_risk) else 20 if any(t in at for t in med_risk) else 10

        ueba_score    = min(20, len(ueba_anomalies) * 7)
        anomaly_score = 15 if is_anomaly else 0
        total         = min(100, sev_score + inherent + ueba_score + anomaly_score)

        entity_id = log_dict.get("source_ip") or log_dict.get("ip_address", "unknown")
        self._history[entity_id].append({"risk": total, "at": datetime.utcnow().isoformat()})
        if len(self._history[entity_id]) > 200:
            self._history[entity_id] = self._history[entity_id][-200:]

        return {
            "entity_id": entity_id,
            "score":     total,
            "signal_breakdown": {
                "severity": sev_score,
                "inherent": inherent,
                "ueba":     ueba_score,
                "anomaly":  anomaly_score,
            },
        }

    def get_entity_history(self, entity_id: str) -> dict:
        hist = self._history.get(entity_id, [])
        if not hist:
            return {"entity_id": entity_id, "events": [], "avg_risk": 0, "trend": "stable"}
        risks = [h["risk"] for h in hist]
        avg   = sum(risks) / len(risks)
        trend = "stable"
        if len(risks) >= 10:
            recent = sum(risks[-5:]) / 5
            prev   = sum(risks[-10:-5]) / 5
            if recent > prev * 1.15:
                trend = "rising"
            elif recent < prev * 0.85:
                trend = "falling"
        return {
            "entity_id":        entity_id,
            "events":           hist[-20:],
            "avg_risk":         round(avg, 1),
            "trend":            trend,
            "high_risk_events": sum(1 for r in risks if r >= 60),
        }

    def get_top_risky_entities(self, n: int = 10) -> list:
        results = []
        for entity_id, hist in self._history.items():
            if not hist:
                continue
            risks  = [h["risk"] for h in hist]
            avg    = sum(risks) / len(risks)
            recent = sum(risks[-5:]) / min(5, len(risks))
            prev   = sum(risks[:-5]) / max(1, len(risks) - 5) if len(risks) > 5 else avg
            trend  = "rising" if recent > prev * 1.15 else "falling" if recent < prev * 0.85 else "stable"
            results.append({
                "entity_id":        entity_id,
                "avg_risk":         round(avg, 1),
                "trend":            trend,
                "high_risk_events": sum(1 for r in risks if r >= 60),
            })
        results.sort(key=lambda x: -x["avg_risk"])
        return results[:n]


# ──────────────────────────────────────────────────────────────
# Entity Graph — attack chain tracking
# ──────────────────────────────────────────────────────────────
class EntityGraph:
    def __init__(self) -> None:
        self._sequences:      dict[str, list] = defaultdict(list)
        self._detected_chains: dict[str, list] = defaultdict(list)

    def add_event(self, entity_id: str, attack_type: str) -> list:
        """Append event and detect chain patterns. Returns matched chains."""
        now = datetime.utcnow()
        self._sequences[entity_id].append((now, attack_type.lower()))

        cutoff = now - timedelta(minutes=30)
        self._sequences[entity_id] = [
            (t, a) for t, a in self._sequences[entity_id] if t >= cutoff
        ]

        recent_types = [a for _, a in self._sequences[entity_id]]
        matched = []
        for cp in CHAIN_PATTERNS:
            idx = 0
            for rt in recent_types:
                if idx < len(cp["pattern"]) and cp["pattern"][idx] in rt:
                    idx += 1
            if idx == len(cp["pattern"]):
                entry = {**cp, "matched_at": now.isoformat()}
                matched.append(entry)
                self._detected_chains[entity_id].append({
                    "pattern_name": cp["pattern_name"],
                    "matched_at":   now.isoformat(),
                })
        return matched

    def get_entity_graph(self, entity_id: str) -> dict:
        recent = self._sequences.get(entity_id, [])
        return {
            "entity_id":       entity_id,
            "recent_events":   [(t.isoformat(), a) for t, a in recent[-20:]],
            "detected_chains": self._detected_chains.get(entity_id, [])[-10:],
        }


# ──────────────────────────────────────────────────────────────
# Anomaly Detector — IsolationForest with statistical fallback
# ──────────────────────────────────────────────────────────────
class AnomalyDetector:
    def __init__(self) -> None:
        self._model:   object = None
        self._scaler:  object = None
        self._buffer:  list   = []
        self._trained: bool   = False

    def _featurize(self, log_dict: dict) -> list:
        sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        sev     = sev_map.get((log_dict.get("severity") or "medium").lower(), 2)
        payload = len(str(log_dict.get("payload") or log_dict.get("body") or ""))
        status  = int(log_dict.get("status_code") or 0)
        req_sz  = int(log_dict.get("request_size") or 0)
        hour    = datetime.utcnow().hour
        return [sev, min(payload, 5000), status, min(req_sz, 100_000), hour]

    def update_and_predict(self, log_dict: dict) -> bool:
        vec = self._featurize(log_dict)
        self._buffer.append(vec)

        if not SKLEARN_AVAILABLE:
            return self._statistical_anomaly(vec)

        if len(self._buffer) >= 20 and len(self._buffer) % 100 == 0:
            self._retrain()

        if self._trained and self._model and self._scaler:
            scaled = self._scaler.transform([vec])
            return self._model.predict(scaled)[0] == -1
        return False

    def _retrain(self) -> None:
        try:
            data   = np.array(self._buffer[-500:])
            scaler = StandardScaler()
            scaled = scaler.fit_transform(data)
            model  = IsolationForest(contamination=0.1, random_state=42)
            model.fit(scaled)
            self._scaler  = scaler
            self._model   = model
            self._trained = True
        except Exception as e:
            print(f"AnomalyDetector retrain error: {e}")

    def _statistical_anomaly(self, vec: list) -> bool:
        if len(self._buffer) < 10:
            return False
        arr  = np.array(self._buffer)
        mean = arr.mean(axis=0)
        std  = arr.std(axis=0) + 1e-9
        z    = np.abs((np.array(vec) - mean) / std)
        return bool(z.max() > 3.0)

    def load(self, path: str) -> bool:
        """Load a pre-trained model from disk. Returns True on success."""
        try:
            import joblib
            model_path = Path(path).resolve()
            allowed_dir = MODEL_DIR.resolve()
            # Reject paths outside the expected models directory
            if not str(model_path).startswith(str(allowed_dir)):
                print(f"AnomalyDetector load error: path outside allowed directory: {path}")
                return False
            if not model_path.exists():
                return False
            bundle = joblib.load(str(model_path))
            self._model   = bundle["model"]
            self._scaler  = bundle["scaler"]
            self._trained = True
            return True
        except Exception as e:
            print(f"AnomalyDetector load error ({path}): {e}")
            return False

    def save(self, path: str) -> bool:
        """Persist current model to disk. Returns True on success."""
        if not (self._trained and self._model and self._scaler):
            return False
        try:
            import joblib
            joblib.dump({"model": self._model, "scaler": self._scaler}, path)
            return True
        except Exception as e:
            print(f"AnomalyDetector save error: {e}")
            return False


# ──────────────────────────────────────────────────────────────
# Threat labeller
# ──────────────────────────────────────────────────────────────
def label_threat(log_dict: dict, risk_score: int) -> tuple[str, str]:
    at = (log_dict.get("attack_type") or log_dict.get("event_type") or "").lower()

    mitre = next((tactic for key, tactic in MITRE_MAP.items() if key in at), "Unknown")

    # Default label from score
    if risk_score >= 80:
        label = "CRITICAL THREAT"
    elif risk_score >= 60:
        label = "HIGH RISK"
    elif risk_score >= 40:
        label = "SUSPICIOUS"
    else:
        label = "LOW RISK"

    # Refine from attack type
    type_labels = {
        "sql":       "SQL Injection",
        "brute":     "Brute Force",
        "command":   "Command Injection",
        "xss":       "XSS",
        "admin":     "Privilege Escalation",
        "geo":       "Impossible Travel",
        "traversal": "Path Traversal",
        "rce":       "Remote Code Execution",
    }
    for key, lbl in type_labels.items():
        if key in at:
            label = lbl
            break

    return label, mitre


# ──────────────────────────────────────────────────────────────
# MLPipeline — public interface used by main.py
# ──────────────────────────────────────────────────────────────
class MLPipeline:
    def __init__(self) -> None:
        self.ueba             = UEBAEngine()
        self.risk             = RiskScorer()
        self.graph            = EntityGraph()
        self.anomaly          = AnomalyDetector()
        self._total_analyzed  = 0
        self._models_loaded: dict[str, bool] = {
            "anomaly_detection": False,
            "ueba_profiles":     False,
        }

    def load(self) -> None:
        """Load pre-trained models from data/models/ if available."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        anomaly_path = MODEL_DIR / "anomaly_detector.joblib"
        if anomaly_path.exists():
            ok = self.anomaly.load(str(anomaly_path))
            self._models_loaded["anomaly_detection"] = ok
            if ok:
                print(f"ML: anomaly detector loaded from {anomaly_path}")

        ueba_path = MODEL_DIR / "ueba_profiles.json"
        if ueba_path.exists():
            ok = self.ueba.load_profiles(str(ueba_path))
            self._models_loaded["ueba_profiles"] = ok
            if ok:
                print(f"ML: {len(self.ueba._profiles)} UEBA profiles loaded from {ueba_path}")

    def _fast_statistical_score(self, log_dict: dict) -> dict:
        """
        Pure-arithmetic scoring under 1ms. No model, no loops over profiles.
        Uses string pattern matching on payload/message for UEBA flags.
        """
        severity = str(log_dict.get('severity', 'info')).lower()
        sev_score = {'critical': 40, 'high': 30, 'medium': 20, 'low': 10, 'info': 5}.get(severity, 5)

        payload = str(log_dict.get('payload', '') or '').lower()
        message = str(log_dict.get('message', '') or '').lower()
        at      = str(log_dict.get('attack_type', '') or log_dict.get('event_type', '') or '').lower()
        text    = payload + ' ' + message + ' ' + at

        anomaly_score = 0.0
        ueba_flags: list = []

        # Fast pattern checks — no regex, pure string contains
        _checks = (
            ('nmap',        0.4, 'nmap_scan'),
            ('sqlmap',      0.5, 'sql_injection_tool'),
            ('../',         0.3, 'path_traversal'),
            ('cmd.exe',     0.4, 'command_execution'),
            ('/bin/sh',     0.4, 'shell_execution'),
            ('select ',     0.3, 'sql_injection'),
            ('<script',     0.3, 'xss_attempt'),
            ('union ',      0.3, 'sql_union'),
            ('base64',      0.2, 'encoded_payload'),
            ('powershell',  0.4, 'powershell'),
            ('wget ',       0.3, 'download_attempt'),
            ('curl ',       0.2, 'curl_command'),
            ('bruteforce',  0.5, 'brute_force'),
            ('brute force', 0.5, 'brute_force'),
            ('port scan',   0.4, 'port_scan'),
        )
        for pattern, weight, flag in _checks:
            if pattern in text:
                anomaly_score += weight
                if flag not in ueba_flags:
                    ueba_flags.append(flag)

        status = int(log_dict.get('status_code', 0) or 0)
        if status == 401: anomaly_score += 0.15; ueba_flags.append('auth_failure')
        elif status == 403: anomaly_score += 0.10
        elif status == 500: anomaly_score += 0.10

        anomaly_score = min(1.0, round(anomaly_score, 4))
        is_anomaly    = anomaly_score >= 0.5

        ueba_contrib = min(20, len(ueba_flags) * 5)
        risk_score   = min(100.0, round(sev_score + anomaly_score * 15 + ueba_contrib, 2))

        threat_label, mitre_tactic = label_threat(log_dict, int(risk_score))

        if risk_score >= 80:   ml_severity = "critical"
        elif risk_score >= 60: ml_severity = "high"
        elif risk_score >= 40: ml_severity = "medium"
        else:                  ml_severity = "low"

        return {
            "severity":        ml_severity,
            "risk_score":      risk_score,
            "anomaly_score":   anomaly_score,
            "threat_label":    threat_label,
            "mitre_tactic":    mitre_tactic,
            "is_anomaly":      is_anomaly,
            "is_ueba_anomaly": bool(ueba_flags),
            "is_sequential":   False,
            "is_novel_log":    False,
            # both naming conventions for compat with _store_ml_result
            "ueba_flags":      ueba_flags,
            "ueba_anomalies":  ueba_flags,
            "attack_chains":   [],
            "attack_chain":    [],
            "model_status":    "statistical_fallback",
            "components": {
                "isolation_forest": anomaly_score,
                "ueba":             ueba_contrib,
                "risk_scorer":      risk_score,
            },
            "risk": {
                "entity_id":        log_dict.get("source_ip") or log_dict.get("ip_address", "unknown"),
                "signal_breakdown": {
                    "severity": sev_score,
                    "inherent": 0,
                    "ueba":     ueba_contrib,
                    "anomaly":  round(anomaly_score * 15, 2),
                },
            },
        }

    def analyze(self, log_dict: dict) -> dict:
        """
        Analyze a log event. Targets under 5ms.
        When IsolationForest is not trained, uses fast statistical scoring.
        Always returns a dict — never None.
        """
        self._total_analyzed += 1
        entity_id = log_dict.get("source_ip") or log_dict.get("ip_address", "unknown")
        at        = (log_dict.get("attack_type") or log_dict.get("event_type") or "unknown").lower()

        try:
            # Fast path when model not yet trained (common case at startup)
            if not self.anomaly._trained:
                result = self._fast_statistical_score(log_dict)
                # Still update UEBA profile in-memory (cheap)
                try:
                    ueba_anomalies = self.ueba.update(log_dict)
                    if ueba_anomalies:
                        combined = list(set(result["ueba_flags"] + ueba_anomalies))
                        result["ueba_flags"]      = combined
                        result["ueba_anomalies"]  = combined
                        result["is_ueba_anomaly"] = True
                except Exception:
                    pass
                # Update anomaly buffer (cheap, enables auto-train later)
                try:
                    self.anomaly.update_and_predict(log_dict)
                except Exception:
                    pass
                return result

            # Trained path: use IsolationForest + full pipeline
            is_anomaly      = self.anomaly.update_and_predict(log_dict)
            ueba_anomalies  = self.ueba.update(log_dict)
            is_ueba_anomaly = bool(ueba_anomalies)
            risk_result     = self.risk.score(log_dict, ueba_anomalies, is_anomaly)
            risk_score      = risk_result["score"]
            chains          = self.graph.add_event(entity_id, at)
            is_novel        = is_anomaly and not ueba_anomalies
            threat_label, mitre_tactic = label_threat(log_dict, risk_score)

            # Also get fast flags for UEBA enrichment
            fast = self._fast_statistical_score(log_dict)
            all_ueba = list(set(fast["ueba_flags"] + ueba_anomalies))

            if risk_score >= 80:   severity = "critical"
            elif risk_score >= 60: severity = "high"
            elif risk_score >= 40: severity = "medium"
            else:                  severity = "low"

            chain_names = [c.get("pattern_name", str(c)) if isinstance(c, dict) else str(c) for c in chains]

            return {
                "severity":        severity,
                "risk_score":      float(risk_score),
                "anomaly_score":   float(fast["anomaly_score"]),
                "threat_label":    threat_label,
                "mitre_tactic":    mitre_tactic,
                "is_anomaly":      is_anomaly or fast["is_anomaly"],
                "is_ueba_anomaly": is_ueba_anomaly or fast["is_ueba_anomaly"],
                "is_sequential":   bool(chains),
                "is_novel_log":    is_novel,
                "ueba_flags":      all_ueba,
                "ueba_anomalies":  all_ueba,
                "attack_chains":   chain_names,
                "attack_chain":    chains,
                "model_status":    "trained",
                "components": {
                    "isolation_forest": float(fast["anomaly_score"]),
                    "ueba":             min(20, len(all_ueba) * 5),
                    "risk_scorer":      float(risk_score),
                },
                "risk": {
                    "entity_id":        entity_id,
                    "signal_breakdown": risk_result["signal_breakdown"],
                },
            }

        except Exception as e:
            import logging
            logging.getLogger(__name__).error("MLPipeline.analyze error: %s", e)
            return self._fast_statistical_score(log_dict)

    def get_ml_summary(self) -> dict:
        return {
            "top_risky_entities":   self.risk.get_top_risky_entities(10),
            "total_entities":       len(self.risk._history),
            "sklearn_available":    SKLEARN_AVAILABLE,
            "models_loaded":        self._models_loaded,
            "total_events_analyzed": self._total_analyzed,
            "ueba_profiles":        len(self.ueba._profiles),
        }
