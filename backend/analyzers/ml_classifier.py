"""Loads the trained classifier and exposes a `predict()` helper that
turns a static-analysis dict into a 13-feature vector used at training time.

The same feature schema is used by `ml_models/train_model.py` so retraining
is just a matter of running that script."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import math

import joblib
import numpy as np

import config

FEATURE_NAMES: List[str] = [
    "size_kb",
    "entropy",
    "section_count",
    "import_dll_count",
    "import_func_count",
    "is_dll",
    "is_driver",
    "is_packed",
    "max_section_entropy",
    "suspicious_api_count",
    "has_network_apis",
    "has_inject_apis",
    "has_crypto_apis",
]

NETWORK_APIS = {"InternetOpenA", "InternetReadFile", "HttpSendRequestA",
                "URLDownloadToFileA", "WSAStartup"}
INJECT_APIS  = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "NtCreateThreadEx"}
CRYPTO_APIS  = {"CryptEncrypt", "CryptGenRandom"}


def featurize(static: Dict[str, Any]) -> List[float]:
    pe = static.get("pe") or {}
    sections = pe.get("sections", [])
    apis = {a["api"] for a in static.get("suspicious_apis", [])}

    return [
        float(static.get("size_bytes", 0)) / 1024.0,
        float(static.get("entropy", 0.0)),
        float(len(sections)),
        float(pe.get("import_dll_count", 0)),
        float(pe.get("import_func_count", 0)),
        float(1 if pe.get("is_dll") else 0),
        float(1 if pe.get("is_driver") else 0),
        float(1 if static.get("packer_hints") else 0),
        float(max((s["entropy"] for s in sections), default=0.0)),
        float(len(apis)),
        float(1 if apis & NETWORK_APIS else 0),
        float(1 if apis & INJECT_APIS  else 0),
        float(1 if apis & CRYPTO_APIS  else 0),
    ]


_model_cache: Dict[str, Any] = {}


def _load_model() -> Any | None:
    if "model" in _model_cache:
        return _model_cache["model"]
    p = Path(config.MODEL_PATH)
    if not p.exists():
        _model_cache["model"] = None
        return None
    try:
        bundle = joblib.load(p)
        _model_cache["model"] = bundle
        return bundle
    except Exception:
        _model_cache["model"] = None
        return None


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def predict(static: Dict[str, Any]) -> Dict[str, Any]:
    """Score the sample with the trained Isolation Forest.

    Isolation Forest is an unsupervised anomaly detector. We:
      1. Pass the static-analysis feature vector through the scaler.
      2. Get the IF decision_function — higher value means "more normal."
      3. Negate + sigmoid-squash to 0..1 so it's comparable to a probability,
         which we expose as `malicious_probability`.
      4. Use IF's own `predict()` (returns -1 for anomaly, +1 for normal)
         to set the `is_anomaly` flag and the binary `label`.
    """
    bundle = _load_model()
    feats = featurize(static)
    if bundle is None:
        return {
            "available":             False,
            "malicious_probability": None,
            "anomaly_score":         None,
            "label":                 None,
            "features":              dict(zip(FEATURE_NAMES, feats)),
            "note":                  "Model file not found; train via "
                                     "ml_models/train_model.py.",
        }

    model   = bundle["model"]
    scaler  = bundle.get("scaler")
    kind    = bundle.get("model_kind", "supervised")
    metrics = bundle.get("metrics", {}) or {}

    x = np.array(feats, dtype=float).reshape(1, -1)
    if scaler is not None:
        x = scaler.transform(x)

    # ----- Isolation-Forest (anomaly) path ----------------------------------
    if kind == "anomaly":
        # decision_function: higher = more normal
        raw           = float(model.decision_function(x)[0])
        anomaly_score = round(_sigmoid(-raw * 4), 4)        # 0..1, high = mal
        is_anomaly    = bool(model.predict(x)[0] == -1)
        label         = "malicious" if is_anomaly else "benign"

        return {
            "available":             True,
            "malicious_probability": anomaly_score,   # IF's anomaly score IS the verdict
            "anomaly_score":         anomaly_score,
            "is_anomaly":            is_anomaly,
            "raw_decision":          round(raw, 4),
            "label":                 label,
            "features":              dict(zip(FEATURE_NAMES, feats)),
            "model_algorithm":       bundle.get("model_name", "isolation_forest"),
            "model_version":         bundle.get("version", "3.0"),
            "metrics":               {
                "test_auc":               metrics.get("test_auc"),
                "supervised_comparison":  metrics.get("supervised_comparison"),
            },
        }

    # ----- Legacy supervised path (kept for backward compatibility) ---------
    proba = float(model.predict_proba(x)[0, 1])
    label = "malicious" if proba >= 0.5 else "benign"
    return {
        "available":             True,
        "malicious_probability": round(proba, 4),
        "anomaly_score":         None,
        "is_anomaly":            None,
        "label":                 label,
        "features":              dict(zip(FEATURE_NAMES, feats)),
        "model_algorithm":       bundle.get("model_name", "?"),
        "model_version":         bundle.get("version", "1.0"),
        "metrics":               {
            "test_auc": metrics.get("test_auc"),
        },
    }
