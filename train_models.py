
import json
import os
import sys
import traceback
from pathlib import Path

# Windows subprocess / console capture uses cp1252 by default; ASCII-safe prints below.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent
DATA_DIR    = BASE_DIR / "data"
MODELS_DIR  = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

# ── Hyper-parameters ───────────────────────────────────────────────────────────
RANDOM_STATE    = 42
TOP_K_FEATURES  = 30   # Number of features selected by mutual-info SelectKBest
VAL_SIZE        = 0.15 # Fraction of training data used as validation split
TEST_SIZE       = 0.15 # Fraction of the full data used as the held-out test split

# ── NSL-KDD file paths ─────────────────────────────────────────────────────────
NSL_TRAIN_PATH = DATA_DIR / "KDDTrain+.TXT"
NSL_TEST_PATH  = DATA_DIR / "KDDTest+.TXT"

# ── Optional UNSW-NB15 paths (used only if both files exist) ───────────────────
UNSW_TRAIN_PATH = DATA_DIR / "UNSW_NB15_training-set.csv"
UNSW_TEST_PATH  = DATA_DIR / "UNSW_NB15_testing-set.csv"

# ── NSL-KDD 43-column header (41 features + attack_name + difficulty) ──────────
NSL_COLUMN_NAMES = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "attack_name","difficulty",
]

# ── NSL-KDD attack-name → canonical family ─────────────────────────────────────
NSL_DOS_ATTACKS   = {"back","land","neptune","pod","smurf","teardrop","apache2","mailbomb","processtable","udpstorm","worm"}
NSL_PROBE_ATTACKS = {"ipsweep","nmap","portsweep","satan","mscan","saint"}
NSL_U2R_ATTACKS   = {"buffer_overflow","loadmodule","perl","rootkit","httptunnel","ps","sqlattack","xterm"}
NSL_R2L_ATTACKS   = {"ftp_write","guess_passwd","imap","multihop","phf","spy","warezclient","warezmaster","sendmail","named","snmpgetattack","snmpguess","xlock","xsnoop"}


def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def map_attack_category(name: str) -> str:
    """Map NSL-KDD specific attack names to the five canonical family labels."""
    name = str(name).strip().lower()
    if name == "normal":      return "Normal"
    if name in NSL_DOS_ATTACKS:   return "DoS"
    if name in NSL_PROBE_ATTACKS: return "Probe"
    if name in NSL_U2R_ATTACKS:   return "U2R"
    if name in NSL_R2L_ATTACKS:   return "R2L"
    return "Unknown"   # will be filtered out below


def basic_cleaning(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf values and clip numeric outliers at 1st/99th percentile."""
    df = df.copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for col in numeric_cols:
        q1  = df[col].quantile(0.01)
        q99 = df[col].quantile(0.99)
        df[col] = df[col].clip(lower=q1, upper=q99)
    return df


def build_preprocessor(X: pd.DataFrame, categorical_cols: list):
    """
    Build a ColumnTransformer that:
    - Imputes median for numeric columns + applies StandardScaler
    - Imputes most_frequent for categorical columns + applies OneHotEncoder
    """
    numeric_cols = [col for col in X.columns if col not in categorical_cols]

    numeric_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler",  StandardScaler()),
    ])
    categorical_transformer = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot",  OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    return ColumnTransformer(transformers=[
        ("num", numeric_transformer,     numeric_cols),
        ("cat", categorical_transformer, categorical_cols),
    ])


def build_pipeline(preprocessor):
    """
    Full training pipeline:
    1. Preprocessing (scaling + encoding)
    2. Feature selection via mutual information (top K features)
    3. SMOTE oversampling (applied only during fit, not predict)
    4. Soft Voting Ensemble of LR + DT + RF
    """
    final_classifier = VotingClassifier(
        estimators=[
            ("lr", LogisticRegression(
                max_iter=2000, random_state=RANDOM_STATE, solver="lbfgs")),
            ("dt", DecisionTreeClassifier(
                random_state=RANDOM_STATE,
                max_depth=18, min_samples_split=6, min_samples_leaf=3)),
            ("rf", RandomForestClassifier(
                n_estimators=250, random_state=RANDOM_STATE,
                n_jobs=-1, class_weight="balanced_subsample")),
        ],
        voting="soft",
    )
    return ImbPipeline(steps=[
        ("preprocessor",   preprocessor),
        ("feature_select", SelectKBest(score_func=mutual_info_classif, k=TOP_K_FEATURES)),
        ("smote",          SMOTE(random_state=RANDOM_STATE)),
        ("classifier",     final_classifier),
    ])


def compute_extended_metrics(y_true_enc, y_pred_enc, y_proba, le: LabelEncoder,
                              class_positive_label: str = "Normal") -> dict:
    """
    Compute the full metric set needed by the Analysis page:
    accuracy, weighted precision/recall/F1, false positive rate, detection rate, AUC.
    Also returns the full per-class classification_report dict.
    """
    acc = float(accuracy_score(y_true_enc, y_pred_enc))

    prec_w  = float(precision_score(y_true_enc, y_pred_enc, average="weighted", zero_division=0))
    rec_w   = float(recall_score(   y_true_enc, y_pred_enc, average="weighted", zero_division=0))
    f1_w    = float(f1_score(       y_true_enc, y_pred_enc, average="weighted", zero_division=0))

    # False positive rate: fraction of Normal records mis-classified as Attack
    classes = le.classes_.tolist()
    if class_positive_label in classes:
        normal_idx    = list(classes).index(class_positive_label)
        is_normal     = (y_true_enc == normal_idx)
        pred_not_norm = (y_pred_enc != normal_idx)
        fpr = float(np.sum(is_normal & pred_not_norm) / max(np.sum(is_normal), 1))
    else:
        fpr = 0.0

    # Detection rate: fraction of actual attack records correctly identified as attack
    if class_positive_label in classes:
        normal_idx   = list(classes).index(class_positive_label)
        is_attack    = (y_true_enc != normal_idx)
        pred_attack  = (y_pred_enc != normal_idx)
        detection_rate = float(np.sum(is_attack & pred_attack) / max(np.sum(is_attack), 1))
    else:
        detection_rate = float(rec_w)

    # AUC (Normal vs. All Attacks — binary OvA for the Normal class)
    auc = 0.0
    if y_proba is not None and class_positive_label in classes:
        normal_idx = list(classes).index(class_positive_label)
        y_binary   = (y_true_enc == normal_idx).astype(int)
        try:
            auc = float(roc_auc_score(y_binary, y_proba[:, normal_idx]))
        except Exception:
            auc = 0.0

    # Per-class classification report as a dict
    report_dict = classification_report(
        y_true_enc, y_pred_enc,
        target_names=classes,
        output_dict=True,
        zero_division=0,
    )

    return {
        "accuracy":               round(acc, 4),
        "precision_weighted":     round(prec_w, 4),
        "recall_weighted":        round(rec_w, 4),
        "f1_weighted":            round(f1_w, 4),
        "false_positive_rate":    round(fpr, 4),
        "detection_rate":         round(detection_rate, 4),
        "auc_normal_vs_attack":   round(auc, 4),
        "classification_report":  report_dict,
    }


def evaluate_individual_algorithms(X_train, y_train_enc, X_val, y_val_enc,
                                    preprocessor, le: LabelEncoder) -> dict:
    """
    Train each algorithm individually on the training split and evaluate on
    the validation split. This populates the 'validation_results' section of
    training_summary.json — used by the Algorithm Comparison chart on the
    Analysis page.
    """
    algorithms = {
        "Logistic Regression": LogisticRegression(
            max_iter=2000, random_state=RANDOM_STATE, solver="lbfgs"),
        "Decision Tree": DecisionTreeClassifier(
            random_state=RANDOM_STATE, max_depth=18, min_samples_split=6, min_samples_leaf=3),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, random_state=RANDOM_STATE, n_jobs=-1,  # smaller n_estimators for speed
            class_weight="balanced_subsample"),
    }
    results = {}
    for algo_name, algo in algorithms.items():
        print(f"  Evaluating {algo_name}...")
        try:
            # Build a lightweight pipeline with same preprocessing + feature selection
            pipe = Pipeline(steps=[
                ("preprocessor",   preprocessor),
                ("feature_select", SelectKBest(score_func=mutual_info_classif, k=TOP_K_FEATURES)),
                ("classifier",     algo),
            ])
            pipe.fit(X_train, y_train_enc)
            pred    = pipe.predict(X_val)
            proba   = pipe.predict_proba(X_val) if hasattr(algo, "predict_proba") else None
            metrics = compute_extended_metrics(y_val_enc, pred, proba, le)
            results[algo_name] = metrics
            print(f"    -> accuracy: {metrics['accuracy']:.4f}, fpr: {metrics['false_positive_rate']:.4f}")
        except Exception as exc:
            print(f"    -> FAILED: {exc}")
            results[algo_name] = {"accuracy": 0.0, "error": str(exc)}
    return results


def train_nsl_kdd() -> dict:
    """
    Full NSL-KDD training run that produces:
    - The trained Soft Voting Ensemble (ids_model.joblib)
    - The label encoder (label_encoder.joblib)
    - A complete training_summary.json with all metrics for the Analysis page

    DATA SOURCE: data/KDDTrain+.TXT and data/KDDTest+.TXT (NSL-KDD benchmark)
    NOT USED: uploaded CSVs, feedback DB records, live traffic, or UNSW-NB15

    SPLIT STRATEGY:
    - Load KDDTrain+.TXT and KDDTest+.TXT, concatenate them
    - Split 70% train / 15% validation / 15% test using stratified splits
    - Validation set: used for individual algorithm evaluation
    - Test set: used for final ensemble evaluation (reported on Analysis page)
    - Cross-validation: 5-fold on the train portion only
    """
    print("Loading NSL-KDD dataset...")
    train_df = pd.read_csv(NSL_TRAIN_PATH, names=NSL_COLUMN_NAMES)
    test_df  = pd.read_csv(NSL_TEST_PATH,  names=NSL_COLUMN_NAMES)

    # Combine both files then re-split — gives a clean, controlled split
    df = pd.concat([train_df, test_df], ignore_index=True)
    print(f"  Combined dataset: {len(df)} records")

    # Map attack names → canonical families
    df["target"] = df["attack_name"].apply(map_attack_category)
    df = df[df["target"] != "Unknown"].copy()
    df = basic_cleaning(df)

    X = df.drop(columns=["attack_name", "difficulty", "target"])
    y = df["target"]
    print(f"  After filtering: {len(X)} records, classes: {sorted(y.unique())}")

    # Step 1: split off 15% test set (stratified)
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

    # Step 2: split remaining into train (82.4% of trainval) and val (17.6% → ~15% of total)
    val_fraction = VAL_SIZE / (1.0 - TEST_SIZE)   # e.g. 0.15 / 0.85 ≈ 0.176
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=val_fraction, random_state=RANDOM_STATE, stratify=y_trainval)

    print(f"  Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # Encode labels
    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_val_enc   = le.transform(y_val)
    y_test_enc  = le.transform(y_test)

    categorical_cols = ["protocol_type", "service", "flag"]
    preprocessor     = build_preprocessor(X_train, categorical_cols)

    # ── Evaluate individual algorithms on validation split ─────────────────────
    print("Evaluating individual algorithms on validation split...")
    validation_results = evaluate_individual_algorithms(
        X_train, y_train_enc, X_val, y_val_enc, preprocessor, le)

    # ── Train the full Soft Voting Ensemble ─────────────────────────────────────
    print("Training Soft Voting Ensemble...")
    full_pipeline = build_pipeline(preprocessor)

    # 5-fold cross-validation on the training split
    print("Running 5-fold cross-validation...")
    cv           = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores    = cross_val_score(
        full_pipeline, X_train, y_train_enc, cv=cv, scoring="accuracy", n_jobs=1)
    print(f"  CV scores: {[round(s,4) for s in cv_scores.tolist()]}")
    print(f"  CV mean: {np.mean(cv_scores):.4f}")

    # Fit on full training split
    full_pipeline.fit(X_train, y_train_enc)

    # Evaluate on held-out test split
    print("Evaluating on test split...")
    test_pred  = full_pipeline.predict(X_test)
    test_proba = full_pipeline.predict_proba(X_test) if hasattr(full_pipeline, "predict_proba") else None
    test_metrics = compute_extended_metrics(y_test_enc, test_pred, test_proba, le)
    print(f"  Test accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  Test FPR: {test_metrics['false_positive_rate']:.4f}")
    print(f"  Test detection rate: {test_metrics['detection_rate']:.4f}")

    # ── Save model artifacts ────────────────────────────────────────────────────
    joblib.dump(full_pipeline, MODELS_DIR / "ids_model.joblib")
    joblib.dump(le,            MODELS_DIR / "label_encoder.joblib")
    print("Model artifacts saved.")

    # ── Build complete training_summary.json ────────────────────────────────────
    # This is the file the Analysis page reads. It must contain the full metrics
    # structure matching the format expected by build_analysis_data() in app.py.
    training_summary = {
        "dataset":               "nsl_kdd",
        "selected_k_features":   TOP_K_FEATURES,
        "unknown_threshold":     0.60,
        "classes":               le.classes_.tolist(),
        "best_validation_model": max(
            validation_results,
            key=lambda k: validation_results[k].get("accuracy", 0),
            default=""),
        "validation_results":    validation_results,
        "final_model": {
            "name":                       "Soft Voting Ensemble",
            "cv_accuracy_scores":         [round(float(s), 4) for s in cv_scores.tolist()],
            "cv_mean_accuracy":           round(float(np.mean(cv_scores)), 4),
            "test_accuracy":              test_metrics["accuracy"],
            "test_precision_weighted":    test_metrics["precision_weighted"],
            "test_recall_weighted":       test_metrics["recall_weighted"],
            "test_f1_weighted":           test_metrics["f1_weighted"],
            "test_false_positive_rate":   test_metrics["false_positive_rate"],
            "test_detection_rate":        test_metrics["detection_rate"],
            "test_auc_normal_vs_attack":  test_metrics["auc_normal_vs_attack"],
            "classification_report":      test_metrics["classification_report"],
        },
    }

    # Write the primary summary file — this is what app.py reads for the Analysis page
    summary_path = REPORTS_DIR / "training_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(training_summary, f, indent=2, ensure_ascii=False)
    print(f"Saved: {summary_path}")

    # Also write the legacy dual summary for backward compatibility
    dual_summary = {
        "nsl_kdd": {
            "dataset":          "nsl_kdd",
            "accuracy":         test_metrics["accuracy"],
            "cv_mean_accuracy": round(float(np.mean(cv_scores)), 4),
            "classes":          le.classes_.tolist(),
        }
    }
    dual_path = REPORTS_DIR / "training_summary_dual.json"
    with open(dual_path, "w", encoding="utf-8") as f:
        json.dump(dual_summary, f, indent=2, ensure_ascii=False)
    print(f"Saved: {dual_path}")

    return training_summary


def train_unsw_nb15() -> dict:
    """
    Optional UNSW-NB15 training run. Only executed if both dataset files exist.

    NOTE ON UNSW-NB15 INTEGRATION:
    UNSW-NB15 uses different feature names, different attack categories, and
    different preprocessing requirements than NSL-KDD. Merging both into one
    model requires careful feature harmonization and risks label confusion.

    Current behavior: if UNSW files are present, train a separate model
    (unsw_model.joblib) and write unsw metrics to training_summary_dual.json.
    The primary dashboard model (ids_model.joblib) remains NSL-KDD only.

    See UNSW-NB15 section in the design notes for the trade-off analysis.
    """
    print("Loading UNSW-NB15 dataset...")
    train_df = pd.read_csv(UNSW_TRAIN_PATH)
    test_df  = pd.read_csv(UNSW_TEST_PATH)
    df = pd.concat([train_df, test_df], ignore_index=True)
    df.columns = [str(c).strip() for c in df.columns]

    drop_cols = [c for c in ["id","label"] if c in df.columns]
    df = df.drop(columns=drop_cols)

    if "attack_cat" not in df.columns:
        raise ValueError("UNSW CSV files must contain 'attack_cat' column")

    df["attack_cat"] = (df["attack_cat"].astype(str).str.strip()
                        .replace({"": "Normal", "nan": "Normal", "None": "Normal", "-": "Normal"}))
    df = basic_cleaning(df)

    X = df.drop(columns=["attack_cat"])
    y = df["attack_cat"]
    categorical = [c for c in ["proto","service","state"] if c in X.columns]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y)

    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_test_enc  = le.transform(y_test)

    preprocessor  = build_preprocessor(X_train, categorical)
    full_pipeline = build_pipeline(preprocessor)

    cv        = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_val_score(full_pipeline, X_train, y_train_enc, cv=cv, scoring="accuracy", n_jobs=1)
    full_pipeline.fit(X_train, y_train_enc)

    pred      = full_pipeline.predict(X_test)
    proba     = full_pipeline.predict_proba(X_test) if hasattr(full_pipeline, "predict_proba") else None
    metrics   = compute_extended_metrics(y_test_enc, pred, proba, le, class_positive_label="Normal")

    joblib.dump(full_pipeline, MODELS_DIR / "unsw_model.joblib")
    joblib.dump(le,            MODELS_DIR / "unsw_label_encoder.joblib")
    print(f"UNSW-NB15 model saved. Accuracy: {metrics['accuracy']:.4f}")

    return {
        "dataset":          "unsw_nb15",
        "accuracy":         metrics["accuracy"],
        "cv_mean_accuracy": round(float(np.mean(cv_scores)), 4),
        "classes":          le.classes_.tolist(),
        "fpr":              metrics["false_positive_rate"],
        "detection_rate":   metrics["detection_rate"],
        "auc":              metrics["auc_normal_vs_attack"],
    }


def main() -> int:
    print("=" * 64)
    print("Waqqas IDS — Model Training Pipeline")
    print("=" * 64)
    print()
    print("DATA SOURCE: NSL-KDD benchmark dataset (KDDTrain+.TXT / KDDTest+.TXT)")
    print("NOT INCLUDED: uploaded traffic, analyst feedback, live capture")
    print()

    ensure_dirs()
    dual_results = {}
    exit_code = 0

    if not NSL_TRAIN_PATH.exists() or not NSL_TEST_PATH.exists():
        print(f"ERROR: NSL-KDD files required at:\n  {NSL_TRAIN_PATH}\n  {NSL_TEST_PATH}")
        return 1

    print("NSL-KDD files found. Starting primary model training...")
    try:
        nsl_summary = train_nsl_kdd()
    except Exception:
        print("NSL-KDD training failed:")
        print(traceback.format_exc())
        return 1

    dual_results["nsl_kdd"] = {
        "dataset":          nsl_summary["dataset"],
        "accuracy":         nsl_summary["final_model"]["test_accuracy"],
        "cv_mean_accuracy": nsl_summary["final_model"]["cv_mean_accuracy"],
        "classes":          nsl_summary["classes"],
    }
    print()
    print("NSL-KDD training complete.")
    print(f"  Accuracy:       {nsl_summary['final_model']['test_accuracy']:.4f}")
    print(f"  FPR:            {nsl_summary['final_model']['test_false_positive_rate']:.4f}")
    print(f"  Detection Rate: {nsl_summary['final_model']['test_detection_rate']:.4f}")
    print(f"  AUC:            {nsl_summary['final_model']['test_auc_normal_vs_attack']:.4f}")

    if UNSW_TRAIN_PATH.exists() and UNSW_TEST_PATH.exists():
        print()
        print("UNSW-NB15 files found. Training secondary model...")
        try:
            dual_results["unsw_nb15"] = train_unsw_nb15()
        except Exception as exc:
            print(f"UNSW-NB15 training failed: {exc}")
            dual_results["unsw_nb15"] = {"error": str(exc)}
    else:
        print()
        print(f"UNSW-NB15 files not found at {UNSW_TRAIN_PATH} — skipping.")

    dual_path = REPORTS_DIR / "training_summary_dual.json"
    with open(dual_path, "w", encoding="utf-8") as f:
        json.dump(dual_results, f, indent=2, ensure_ascii=False)

    print()
    print("=" * 64)
    print("Training pipeline complete.")
    print(f"Primary model: {MODELS_DIR / 'ids_model.joblib'}")
    print(f"Metrics file:  {REPORTS_DIR / 'training_summary.json'}")
    print("=" * 64)
    print(json.dumps(dual_results, indent=2, ensure_ascii=False))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
