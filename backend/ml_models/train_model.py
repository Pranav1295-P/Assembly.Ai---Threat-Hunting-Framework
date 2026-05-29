"""Train the Assembly.AI malware classifier.

PRIMARY ALGORITHM:  Isolation Forest  (unsupervised anomaly detection)

Why Isolation Forest:
    - Trained on BENIGN samples only — no labelled malware needed.
    - Detects novel / zero-day samples that supervised models would miss
      because the training set never contained them.
    - Naturally generalises to new malware families without retraining.
    - Lower numerical AUC than supervised baselines on labelled benchmarks,
      but far more robust in real-world deployment where new malware
      variants emerge daily.

For the project writeup we ALSO train Gradient Boosting / Random Forest /
Logistic Regression on the labelled corpus as supervised baselines, so the
report can show a side-by-side comparison. Only the Isolation Forest is
persisted for inference; the supervised comparison numbers are stored
inside the bundle's `metrics` field.

Run:
    python ml_models/train_model.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble        import (GradientBoostingClassifier, IsolationForest,
                                      RandomForestClassifier)
from sklearn.linear_model    import LogisticRegression
from sklearn.metrics         import classification_report, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing   import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config  # noqa: E402

RNG = np.random.default_rng(42)
N_PER_CLASS = 4000
LABEL_NOISE = 0.05      # 5 % mislabelled samples — real corpora have noise


# ---------- harder synthetic distributions --------------------------------
# These overlap a lot more than the previous toy version. They're modelled
# after the per-feature distributions reported in the EMBER-2018 dataset paper,
# scaled down so we keep the pipeline lightweight and reproducible.

def _benign_sample() -> list[float]:
    return [
        max(8,  RNG.normal(900, 700)),                 # size_kb
        np.clip(RNG.normal(5.6, 0.9), 0, 8),           # overall entropy
        max(2,  int(RNG.normal(5.8, 2.0))),            # section_count
        max(1,  int(RNG.normal(9,   4))),              # import_dll_count
        max(8,  int(RNG.normal(140, 65))),             # import_func_count
        int(RNG.random() < 0.22),                       # is_dll
        int(RNG.random() < 0.02),                       # is_driver
        int(RNG.random() < 0.10),                       # is_packed  (was 5 %)
        np.clip(RNG.normal(5.9, 0.9), 0, 8),           # max_section_entropy
        max(0,  int(RNG.normal(2,   1.7))),            # suspicious_api_count
        int(RNG.random() < 0.42),                       # has_network_apis
        int(RNG.random() < 0.04),                       # has_inject_apis
        int(RNG.random() < 0.14),                       # has_crypto_apis
    ]


def _malicious_sample() -> list[float]:
    return [
        max(4,  RNG.normal(520, 600)),                 # size_kb
        np.clip(RNG.normal(6.6, 1.1), 0, 8),           # overlaps benign tail
        max(2,  int(RNG.normal(6.4, 2.3))),
        max(1,  int(RNG.normal(6,   4))),
        max(6,  int(RNG.normal(90,  55))),
        int(RNG.random() < 0.30),
        int(RNG.random() < 0.06),
        int(RNG.random() < 0.45),                       # packed more often
        np.clip(RNG.normal(6.9, 0.9), 0, 8),
        max(0,  int(RNG.normal(5,   2.5))),             # more sus APIs but overlaps
        int(RNG.random() < 0.65),
        int(RNG.random() < 0.45),
        int(RNG.random() < 0.32),
    ]


def build_dataset() -> tuple[np.ndarray, np.ndarray]:
    benign = np.array([_benign_sample()    for _ in range(N_PER_CLASS)])
    malic  = np.array([_malicious_sample() for _ in range(N_PER_CLASS)])
    X = np.vstack([benign, malic])
    y = np.array([0] * N_PER_CLASS + [1] * N_PER_CLASS)

    # Inject label noise — real labelled corpora are never clean.
    n_flip = int(len(y) * LABEL_NOISE)
    flip_idx = RNG.choice(len(y), size=n_flip, replace=False)
    y[flip_idx] = 1 - y[flip_idx]

    perm = RNG.permutation(len(y))
    return X[perm], y[perm]


# ---------- training ------------------------------------------------------

def _eval(name: str, y_true, y_proba) -> float:
    auc = roc_auc_score(y_true, y_proba)
    pred = (y_proba >= 0.5).astype(int)
    print(f"\n[{name}]  ROC-AUC = {auc:.4f}")
    print(classification_report(y_true, pred,
                                target_names=["benign", "malicious"],
                                digits=3))
    return auc


def main() -> None:
    print("=" * 62)
    print("  Assembly.AI · TRAIN v3.0 · ISOLATION FOREST (primary) ")
    print("=" * 62)
    print("[*] Building harder synthetic PE-feature corpus …")
    X, y = build_dataset()
    print(f"    shape : {X.shape}  ·  label-noise : {LABEL_NOISE:.0%}")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2,
                                          stratify=y, random_state=7)
    scaler = StandardScaler().fit(Xtr)
    Xtr_s = scaler.transform(Xtr)
    Xte_s = scaler.transform(Xte)

    # =================================================================
    # PRIMARY: Isolation Forest  (unsupervised anomaly detection)
    # Trained on BENIGN samples only — every malicious sample is meant
    # to be flagged as "not normal."
    # =================================================================
    print("\n[*] Training Isolation Forest on benign samples only …")
    benign_only = Xtr_s[ytr == 0]
    print(f"    benign training set size : {len(benign_only)}")

    iso = IsolationForest(
        n_estimators=400,
        contamination=0.10,       # expected outlier ratio in benign set
        max_samples="auto",
        random_state=7,
        n_jobs=-1,
    )
    iso.fit(benign_only)

    # Evaluation: higher decision_function = more normal,
    # so negate to get "anomaly score" where high = likely malicious.
    iso_test_score = -iso.decision_function(Xte_s)
    iso_test_auc   = roc_auc_score(yte, iso_test_score)
    iso_pred       = (iso.predict(Xte_s) == -1).astype(int)  # -1 = anomaly = mal.

    print(f"\n[Isolation Forest · TEST]  ROC-AUC = {iso_test_auc:.4f}")
    print(classification_report(yte, iso_pred,
                                target_names=["benign", "malicious"],
                                digits=3))

    # =================================================================
    # COMPARISON BASELINES (printed for the report — NOT saved)
    # =================================================================
    print("[*] Supervised baselines for comparison "
          "(NOT used at inference) …")
    baselines = {
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=300, max_depth=3, learning_rate=0.07, random_state=7,
        ),
        "random_forest":     RandomForestClassifier(
            n_estimators=400, max_depth=12, min_samples_leaf=2,
            n_jobs=-1, random_state=7,
        ),
        "logistic_reg":      LogisticRegression(
            max_iter=2000, C=1.0, random_state=7,
        ),
    }
    baseline_aucs: dict[str, float] = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=7)
    for name, m in baselines.items():
        m.fit(Xtr_s, ytr)
        proba = m.predict_proba(Xte_s)[:, 1]
        baseline_aucs[name] = float(roc_auc_score(yte, proba))
        cv_scores = cross_val_score(m, Xtr_s, ytr, cv=cv,
                                    scoring="roc_auc", n_jobs=-1)
        print(f"    {name:18s} : test AUC = {baseline_aucs[name]:.4f}  "
              f"(5-fold CV {cv_scores.mean():.4f} ± {cv_scores.std():.4f})")

    # Best supervised — to print honest delta in the writeup.
    best_sup = max(baseline_aucs, key=baseline_aucs.get)
    delta = baseline_aucs[best_sup] - iso_test_auc
    print(f"\n[+] Selected algorithm : isolation_forest   (test AUC = {iso_test_auc:.4f})")
    print(f"    Best supervised    : {best_sup}   ({baseline_aucs[best_sup]:.4f}, +{delta:.3f})")
    print( "    → Isolation Forest preferred for novel / zero-day robustness.\n")

    # =================================================================
    # Persist bundle — Isolation Forest is the ONLY inference model.
    # =================================================================
    bundle = {
        "model":       iso,
        "model_name":  "isolation_forest",
        "model_kind":  "anomaly",          # tells ml_classifier which path
        "scaler":      scaler,
        "metrics": {
            "test_auc":               float(iso_test_auc),
            "supervised_comparison":  baseline_aucs,
        },
        "feature_names": [
            "size_kb", "entropy", "section_count", "import_dll_count",
            "import_func_count", "is_dll", "is_driver", "is_packed",
            "max_section_entropy", "suspicious_api_count",
            "has_network_apis", "has_inject_apis", "has_crypto_apis",
        ],
        "version": "3.0.0",
    }
    out = Path(config.MODEL_PATH)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out)
    print(f"[+] Saved bundle → {out}  ({out.stat().st_size/1024:.1f} KB)")


if __name__ == "__main__":
    main()
