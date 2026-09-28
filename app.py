
import csv
import io
import json
import os
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

import joblib
import pandas as pd
from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from pandas.errors import EmptyDataError, ParserError
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from utils.label_utils import breakdown_family_css_class, family_chart_color

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR           = Path(__file__).resolve().parent
MODELS_DIR         = BASE_DIR / "models"
UPLOADS_DIR        = BASE_DIR / "uploads"
DATABASE_DIR       = BASE_DIR / "database"
DATABASE_PATH      = DATABASE_DIR / "ids.db"
REPORTS_DIR        = BASE_DIR / "reports"
MODEL_PATH         = MODELS_DIR / "ids_model.joblib"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"

# ── Config ─────────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS   = {"csv"}

# These thresholds are intentionally not exposed in any template (spec F).
UNKNOWN_THRESHOLD    = 0.60   # Below this confidence → "Unknown Suspicious Behavior"
AUTO_BLOCK_THRESHOLD = 0.96   # Above this + critical risk → automatic IP block

DISPLAY_TIMEZONE = ZoneInfo("Africa/Cairo")
DB_DT_FMT        = "%Y-%m-%d %H:%M:%S"
UI_DT_FMT        = "%Y-%m-%d %H:%M:%S"

MAX_LATEST_RESULTS = 100
MAX_LATEST_ALERTS  = 50
MAX_LATEST_NOTES   = 50
RECENT_CONNECTIONS_LIMIT = 20

SOURCE_IP_COLUMN = "source_ip"

# ── NSL-KDD 41 feature columns ─────────────────────────────────────────────────
REQUIRED_FEATURE_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
]

# ── Presentation-layer display label map (UI only — never stored or used for inference) ──
ATTACK_DISPLAY_MAPPING = {
    "normal":                      "Normal Traffic",
    "dos":                         "Denial of Service",
    "probe":                       "Reconnaissance / Scanning",
    "r2l":                         "Credential / Access Abuse",
    "u2r":                         "Privilege Escalation",
    "unknown suspicious behavior": "Unknown Suspicious Behavior",
}

# ── Feedback label alias map — normalizes user-entered labels to canonical form ──
# Prevents retraining pipeline from receiving inconsistent or ambiguous labels.
LABEL_ALIASES = {
    "normal":"Normal","normal traffic":"Normal","benign":"Normal","safe":"Normal",
    "legitimate":"Normal","clean":"Normal",
    "dos":"DoS","denial of service":"DoS","ddos":"DoS",
    "probe":"Probe","recon":"Probe","reconnaissance":"Probe",
    "reconnaissance / scanning":"Probe","scan":"Probe","scanning":"Probe",
    "u2r":"U2R","privilege escalation":"U2R","user to root":"U2R",
    "r2l":"R2L","credential / access abuse":"R2L","credential abuse":"R2L","remote to local":"R2L",
    "unknown suspicious behavior":"Unknown Suspicious Behavior",
    "unknown":"Unknown Suspicious Behavior","suspicious":"Unknown Suspicious Behavior",
}
CANONICAL_LABELS = {"Normal","DoS","Probe","U2R","R2L"}

# ── Attack family keyword sets ─────────────────────────────────────────────────
DOS_ATTACKS   = {"back","land","neptune","pod","smurf","teardrop","mailbomb","apache2","processtable","udpstorm","worm","dos"}
PROBE_ATTACKS = {"ipsweep","nmap","portsweep","satan","mscan","saint","probe","scan"}
R2L_ATTACKS   = {"guess_passwd","ftp_write","imap","multihop","phf","spy","warezclient","warezmaster","sendmail","named","snmpgetattack","snmpguess","httptunnel","xsnoop","xlock","r2l"}
U2R_ATTACKS   = {"buffer_overflow","rootkit","loadmodule","perl","ps","sqlattack","xterm","u2r"}
SAFE_KEYWORDS = {"normal","benign","safe","trusted","allow","allowed","clean","legitimate"}
CRITICAL_ATTACK_KEYWORDS = {"dos","back","land","neptune","pod","smurf","teardrop","mailbomb","apache2","processtable","udpstorm","buffer_overflow","rootkit","loadmodule","perl","ps","sqlattack","xterm","worm"}
DANGER_ATTACK_KEYWORDS   = {"ipsweep","nmap","portsweep","satan","mscan","saint","guess_passwd","ftp_write","imap","multihop","phf","spy","warezclient","warezmaster","sendmail","named","snmpgetattack","snmpguess","httptunnel","xsnoop","xlock","probe","scan","r2l","u2r"}

VALID_FEEDBACK_LABELS = {"false_positive","false_negative","correct","needs_review"}

# ── Background retrain state (thread-safe) ─────────────────────────────────────
_retrain_lock   = threading.Lock()
_retrain_status = {"running": False, "last_result": None, "last_error": None}

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["SECRET_KEY"]         = os.environ.get("WAQQAS_SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_PERMANENT"]  = False


@app.template_filter("breakdown_family_class")
def _breakdown_family_class_filter(label):
    return breakdown_family_css_class(label)

# ── Directory setup ────────────────────────────────────────────────────────────
def ensure_dirs():
    for d in [MODELS_DIR, UPLOADS_DIR, DATABASE_DIR, REPORTS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

# ── Time helpers ───────────────────────────────────────────────────────────────
def utc_now():
    return datetime.now(timezone.utc)

def now_str():
    return utc_now().strftime(DB_DT_FMT)

def fmt_dt(value):
    if not value:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    dt_obj = None
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"]:
        try:
            dt_obj = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            break
        except Exception:
            pass
    if dt_obj is None:
        try:
            dt_obj = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt_obj.tzinfo is None:
                dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        except Exception:
            return raw
    return dt_obj.astimezone(DISPLAY_TIMEZONE).strftime(UI_DT_FMT)

# ── Database ───────────────────────────────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn

def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL UNIQUE, reason TEXT, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ip_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL, note_type TEXT NOT NULL,
            note_text TEXT NOT NULL, created_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS blocked_ip_notes_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL, note_type TEXT NOT NULL, note_text TEXT NOT NULL,
            original_created_at TEXT NOT NULL, archived_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, source_ip TEXT, features_summary TEXT,
            prediction TEXT NOT NULL, confidence REAL NOT NULL,
            is_unknown INTEGER NOT NULL DEFAULT 0,
            is_blocked_ref INTEGER NOT NULL DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER NOT NULL, feedback_label TEXT NOT NULL,
            corrected_label TEXT, created_at TEXT NOT NULL,
            FOREIGN KEY (prediction_id) REFERENCES predictions(id) ON DELETE CASCADE)""")
        conn.commit()

# ── Model loading (lazy — see ensure_bootstrapped) ─────────────────────────────
model = None
label_encoder = None
_bootstrap_done = False

def load_artifacts():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
    if not LABEL_ENCODER_PATH.exists():
        raise FileNotFoundError(f"Label encoder not found: {LABEL_ENCODER_PATH}")
    return joblib.load(MODEL_PATH), joblib.load(LABEL_ENCODER_PATH)

# ── Authentication decorator ───────────────────────────────────────────────────
def login_required(f):
    """
    Route decorator that enforces login. Any unauthenticated request to a
    protected route is redirected to the login page.

    Protected routes: /data, /dashboard, /analysis
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please log in to access the analyst workspace.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ── Label helpers ──────────────────────────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def to_python_type(value):
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    return value

def normalize_columns(columns):
    return [str(c).strip() for c in columns]

def normalize_label_text(label):
    return str(label or "").strip()

def to_display_label(label):
    """
    Presentation-layer transformation only.
    Maps internal/canonical labels → human-readable UI strings.
    Never used for storage, model inference, or retraining.
    """
    normalized = normalize_label_text(label).lower()
    if normalized in ATTACK_DISPLAY_MAPPING:
        return ATTACK_DISPLAY_MAPPING[normalized]
    if normalized in DOS_ATTACKS:    return "Denial of Service"
    if normalized in PROBE_ATTACKS:  return "Reconnaissance / Scanning"
    if normalized in R2L_ATTACKS:    return "Credential / Access Abuse"
    if normalized in U2R_ATTACKS:    return "Privilege Escalation"
    if normalized in SAFE_KEYWORDS:  return "Normal Traffic"
    return normalize_label_text(label)

def resolve_canonical_label(value, allow_unknown=True):
    """
    Map a user-entered or display label back to a canonical model label.
    Used in feedback submission to prevent retraining label corruption.
    Returns None if the label cannot be confidently resolved.
    """
    text = normalize_label_text(value)
    if not text:
        return None
    if text in CANONICAL_LABELS:
        return text
    resolved = LABEL_ALIASES.get(text.lower())
    if resolved == "Unknown Suspicious Behavior" and not allow_unknown:
        return None
    return resolved

# ── Validation ─────────────────────────────────────────────────────────────────
def build_missing_columns_error(df_columns):
    normalized = normalize_columns(df_columns)
    missing    = [c for c in REQUIRED_FEATURE_COLUMNS if c not in normalized]
    return {
        "error_type":"missing_columns","error":"The uploaded file is missing required columns.",
        "message":"The CSV structure does not match the model input format.",
        "missing_columns":missing,"expected_required_count":len(REQUIRED_FEATURE_COLUMNS),
        "found_columns_count":len(normalized),"found_columns":normalized,
        "optional_columns":[SOURCE_IP_COLUMN],
        "example_fix":"Use the trained dataset header/template exactly, then upload again.",
    }

def validate_csv_headers_before_read(file_storage):
    file_storage.stream.seek(0)
    raw_bytes = file_storage.stream.read()
    file_storage.stream.seek(0)
    if not raw_bytes:
        return {"ok":False,"response":{"error_type":"empty_file","error":"The uploaded file is empty.","message":"Please upload a CSV file with headers and data."}}
    try:
        text = raw_bytes.decode("utf-8-sig", errors="replace")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return {"ok":False,"response":{"error_type":"empty_file","error":"No readable rows found.","message":"Please upload a valid CSV file."}}
    try:
        sample  = "\n".join(lines[:5])
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        reader  = csv.reader(io.StringIO(lines[0]), dialect)
        headers = next(reader, [])
    except Exception:
        headers = next(csv.reader(io.StringIO(lines[0])), [])
    headers = normalize_columns(headers)
    if not headers:
        return {"ok":False,"response":{"error_type":"invalid_header","error":"Could not detect CSV headers.","message":"Make sure the first row contains column names."}}
    missing = [c for c in REQUIRED_FEATURE_COLUMNS if c not in headers]
    if missing:
        return {"ok":False,"response":build_missing_columns_error(headers)}
    return {"ok":True,"headers":headers}

def normalize_input_dataframe(df):
    df = df.copy()
    df.columns = normalize_columns(df.columns)
    if SOURCE_IP_COLUMN not in df.columns:
        df[SOURCE_IP_COLUMN] = None
    missing = [c for c in REQUIRED_FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(json.dumps(build_missing_columns_error(df.columns), ensure_ascii=False))
    for col in REQUIRED_FEATURE_COLUMNS:
        if col in ["protocol_type","service","flag"]:
            df[col] = df[col].astype(str).str.strip()
        else:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df[REQUIRED_FEATURE_COLUMNS + [SOURCE_IP_COLUMN]]

def extract_feature_frame(df):
    return df[REQUIRED_FEATURE_COLUMNS].copy()

def build_features_summary(row):
    keys = ["protocol_type","service","flag","src_bytes","dst_bytes","count","srv_count"]
    return json.dumps({k: to_python_type(row.get(k)) for k in keys}, ensure_ascii=False)

# ── Risk classification ────────────────────────────────────────────────────────
def is_ip_blocked(source_ip):
    if not source_ip:
        return False
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT 1 FROM blocked_ips WHERE source_ip = ?", (str(source_ip),))
        return c.fetchone() is not None

def is_safe_label(prediction):
    return any(w in str(prediction or "").lower() for w in SAFE_KEYWORDS)

def is_critical_attack_label(prediction):
    return any(w in str(prediction or "").lower() for w in CRITICAL_ATTACK_KEYWORDS)

def classify_risk_level(prediction, confidence, is_unknown):
    label = str(prediction or "").strip().lower()
    if is_unknown:                                              return "unknown"
    if any(w in label for w in SAFE_KEYWORDS):                 return "safe"
    if any(w in label for w in CRITICAL_ATTACK_KEYWORDS):
        return "critical" if confidence >= 0.85 else "danger"
    if any(w in label for w in DANGER_ATTACK_KEYWORDS):        return "danger"
    if confidence >= 0.98:                                     return "critical"
    if confidence >= 0.90:                                     return "danger"
    return "safe"

def build_decision_reason(prediction, confidence, risk_level, is_unknown, source_ip=None):
    display = to_display_label(prediction)
    if is_unknown:
        return f"Confidence {confidence:.4f} is below the detection threshold — treated as unknown suspicious behavior."
    if is_safe_label(prediction):
        return f"Predicted as '{display}' with confidence {confidence:.4f}. Treated as safe."
    if confidence >= AUTO_BLOCK_THRESHOLD and risk_level in {"danger","critical"} and source_ip:
        return f"Predicted as '{display}' (risk: {risk_level}) with confidence {confidence:.4f}. Met auto-block criteria."
    if risk_level in {"danger","critical"}:
        return f"Predicted as '{display}' (risk: {risk_level}) with confidence {confidence:.4f}. Queued for manual review."
    return f"Predicted as '{display}' with confidence {confidence:.4f}."

def should_auto_block(source_ip, prediction, confidence, is_unknown, risk_level):
    return (source_ip and not is_unknown and not is_safe_label(prediction)
            and risk_level in {"critical","danger"} and confidence >= AUTO_BLOCK_THRESHOLD)

def build_auto_block_reason(source_ip, prediction, confidence, risk_level):
    display = to_display_label(prediction)
    reasons = []
    if is_critical_attack_label(prediction):  reasons.append(f"attack type '{display}' is critical")
    if confidence >= AUTO_BLOCK_THRESHOLD:    reasons.append(f"confidence {confidence:.4f} exceeded auto-block threshold")
    if risk_level == "critical":              reasons.append("risk level was critical")
    if not reasons:                           reasons.append("auto-block policy conditions were satisfied")
    return f"System automatically blocked {source_ip} because {', '.join(reasons)}."

def create_block_note_text(source_ip, prediction, confidence, mode="manual", risk_level=None):
    display = to_display_label(prediction)
    if mode == "auto":
        return build_auto_block_reason(source_ip, prediction, confidence, risk_level or "danger")
    return f"Blocked from dashboard for prediction '{display}' with confidence {confidence:.4f}."

# ── Database writes ────────────────────────────────────────────────────────────
def save_prediction(source_ip, features_summary, prediction, confidence, is_unknown, is_blocked_ref):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO predictions
            (timestamp,source_ip,features_summary,prediction,confidence,is_unknown,is_blocked_ref)
            VALUES (?,?,?,?,?,?,?)""",
            (now_str(), None if source_ip is None else str(source_ip), features_summary,
             str(prediction), float(confidence), int(is_unknown), int(is_blocked_ref)))
        conn.commit()
        return int(c.lastrowid)

def auto_block_ip(source_ip, reason):
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO blocked_ips (id,source_ip,reason,created_at)
            VALUES (COALESCE((SELECT id FROM blocked_ips WHERE source_ip=?),NULL),?,?,?)""",
            (str(source_ip), str(source_ip), str(reason), now_str()))
        c.execute("INSERT INTO blocked_ip_notes (source_ip,note_type,note_text,created_at) VALUES (?,?,?,?)",
                  (str(source_ip),"block",str(reason),now_str()))
        c.execute("UPDATE predictions SET is_blocked_ref=1 WHERE source_ip=?", (str(source_ip),))
        conn.commit()
    return {"source_ip":str(source_ip),"note_type":"block","note_text":str(reason),"created_at":fmt_dt(now_str())}

# ── Alert builder ──────────────────────────────────────────────────────────────
def build_alert_item(source_ip, prediction, display_prediction, confidence, risk_level, auto_blocked):
    title = "Critical threat detected" if risk_level == "critical" else "Suspicious activity detected"
    msg   = (f"Detected {display_prediction} from {source_ip or 'this source'} "
             f"with confidence {confidence:.4f}. "
             f"{'Auto-blocked.' if auto_blocked else 'Manual review recommended.'}")
    return {"title":title,"source_ip":None if source_ip is None else str(source_ip),
            "prediction":str(prediction),"display_prediction":str(display_prediction),
            "confidence":float(round(confidence,4)),"risk_level":str(risk_level),
            "auto_blocked":bool(auto_blocked),"message":msg}

# ── Session helpers ────────────────────────────────────────────────────────────
def trim_list(items, n):
    return list(items[:n]) if isinstance(items, list) else []

def store_latest_upload_state(payload, filename=None):
    session["latest_upload_results"]      = trim_list(payload.get("results",[]), MAX_LATEST_RESULTS)
    session["latest_upload_alert_items"]  = trim_list(payload.get("alert_items",[]), MAX_LATEST_ALERTS)
    session["latest_upload_threat_count"] = int(payload.get("threat_count", 0))
    if filename:
        session["active_dataset_filename"] = str(filename)
    session.modified = True

def clear_latest_upload_state():
    for k in ["latest_upload_results","latest_upload_alert_items",
              "latest_upload_block_notes","latest_upload_threat_count"]:
        session.pop(k, None)
    session.modified = True

def append_pending_note_to_session(note):
    notes = session.get("latest_upload_block_notes", [])
    notes.insert(0, note)
    session["latest_upload_block_notes"] = trim_list(notes, MAX_LATEST_NOTES)
    session.modified = True

def get_latest_upload_state():
    return {
        "results":      session.get("latest_upload_results", []),
        "alert_items":  session.get("latest_upload_alert_items", []),
        "block_notes":  session.get("latest_upload_block_notes", []),
        "threat_count": int(session.get("latest_upload_threat_count", 0)),
        "active_filename": session.get("active_dataset_filename", ""),
    }

def list_saved_csv_files(limit=20):
    files = []
    try:
        paths = sorted(UPLOADS_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in paths[:limit]:
            try:
                st = path.stat()
                files.append({
                    "name": path.name,
                    "rows": None,
                    "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                })
            except OSError:
                continue
    except OSError:
        pass
    return files

def build_family_counts(rows):
    fc = {}
    for row in rows:
        d = row.get("display_prediction") or to_display_label(row.get("prediction",""))
        fc[d] = fc.get(d, 0) + 1
    return [{"prediction":k,"display_prediction":k,"count":v}
            for k,v in sorted(fc.items(), key=lambda x: x[1], reverse=True)]

# ── Prediction pipeline ────────────────────────────────────────────────────────
def predict_dataframe(df):
    """
    Full prediction pipeline:
    1. Normalize and validate the input DataFrame
    2. Run model.predict + model.predict_proba
    3. Apply UNKNOWN_THRESHOLD for low-confidence escalation
    4. Apply AUTO_BLOCK_THRESHOLD for high-confidence auto-blocking
    5. Persist every prediction to SQLite
    6. Return structured results, alert items, block notes

    DATA USED: only the uploaded CSV rows. The model itself was trained on NSL-KDD.
    """
    normalized_df = normalize_input_dataframe(df)
    if normalized_df.empty:
        raise ValueError(json.dumps({
            "error_type":"no_rows","error":"The uploaded file contains no data rows.",
            "message":"Add at least one valid record, then upload again.",
        }, ensure_ascii=False))

    feature_df    = extract_feature_frame(normalized_df)
    encoded_preds = model.predict(feature_df)
    pred_proba    = model.predict_proba(feature_df) if hasattr(model, "predict_proba") else None
    max_conf      = pred_proba.max(axis=1) if pred_proba is not None else [1.0] * len(feature_df)
    decoded_preds = label_encoder.inverse_transform(encoded_preds)

    results = []; alert_items = []; block_notes = []

    for idx, pred_label in enumerate(decoded_preds):
        source_ip  = to_python_type(normalized_df.iloc[idx].get(SOURCE_IP_COLUMN))
        confidence = float(to_python_type(max_conf[idx]))
        is_unknown = bool(confidence < UNKNOWN_THRESHOLD)

        internal_prediction = "Unknown Suspicious Behavior" if is_unknown else str(pred_label)
        display_prediction  = to_display_label(internal_prediction)
        risk_level          = classify_risk_level(internal_prediction, confidence, is_unknown)
        blocked_before      = bool(is_ip_blocked(source_ip) if source_ip else False)
        features_summary    = build_features_summary(normalized_df.iloc[idx])

        prediction_id = save_prediction(
            source_ip=source_ip, features_summary=features_summary,
            prediction=internal_prediction, confidence=confidence,
            is_unknown=is_unknown, is_blocked_ref=blocked_before)

        auto_blocked = False; live_blocked = blocked_before
        if should_auto_block(source_ip, internal_prediction, confidence, is_unknown, risk_level) and not blocked_before:
            reason = create_block_note_text(source_ip, internal_prediction, confidence,
                                            mode="auto", risk_level=risk_level)
            note   = auto_block_ip(source_ip, reason)
            block_notes.append(note)
            auto_blocked = True; live_blocked = True
            with get_db_connection() as conn:
                conn.execute("UPDATE predictions SET is_blocked_ref=1 WHERE id=?", (int(prediction_id),))
                conn.commit()

        decision_reason = build_decision_reason(
            prediction=internal_prediction, confidence=confidence,
            risk_level=risk_level, is_unknown=is_unknown, source_ip=source_ip)

        result_row = {
            "prediction_id":int(prediction_id),"prediction":str(internal_prediction),
            "display_prediction":str(display_prediction),"confidence":float(round(confidence,4)),
            "source_ip":None if source_ip is None else str(source_ip),
            "is_unknown":bool(is_unknown),"is_blocked":bool(live_blocked),
            "risk_level":str(risk_level),"auto_blocked":bool(auto_blocked),
            "decision_reason":decision_reason,
        }
        results.append(result_row)

        if risk_level in {"danger","critical","unknown"}:
            alert_items.append(build_alert_item(
                source_ip, internal_prediction, display_prediction, confidence, risk_level, auto_blocked))

    threat_count = len([r for r in results if r["risk_level"] in {"danger","critical","unknown"}])
    return {
        "results":results,"alert_items":alert_items,"block_notes":block_notes,
        "threat_count":threat_count,"family_counts":build_family_counts(results),
    }

# ── Analysis data builder ──────────────────────────────────────────────────────
def build_analysis_data():
    """
    Loads training_summary.json which is written by train_models.py after each
    training run. This file contains ALL metrics: accuracy, FPR, detection rate,
    AUC, CV scores, per-class report, and algorithm comparison.

    WHEN DO METRICS UPDATE?
    - They update when train_models.py completes a run (via the Retrain button
      or manual execution). The script writes a new training_summary.json.
    - The Analysis page reads this file fresh on every page load — no caching.
    - If training_summary.json does not exist, all metric cards show 0 / empty.
    - After retraining, reload /analysis to see the new values.

    WHY METRICS SHOWED 0% IN PREVIOUS VERSIONS:
    - The previous train_models.py only wrote training_summary_dual.json (minimal).
    - The analysis page reads training_summary.json (full metrics format).
    - Those two files were never the same, so after retraining, metrics never updated.
    - FIXED: train_models.py now writes the full training_summary.json.
    """
    training_summary = None
    metrics_version = 0
    ts_path = REPORTS_DIR / "training_summary.json"
    if ts_path.exists():
        try:
            metrics_version = int(ts_path.stat().st_mtime)
        except OSError:
            metrics_version = 0
    if ts_path.exists():
        try:
            with open(ts_path, "r", encoding="utf-8") as f:
                training_summary = json.load(f)
        except Exception:
            pass

    # Most recent uploaded CSV info (for the Active Dataset panel)
    data_info = None
    csvs = sorted(UPLOADS_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if csvs:
        try:
            df = pd.read_csv(csvs[0])
            df.columns = normalize_columns(df.columns)
            data_info = {"filename":csvs[0].name,"rows":int(df.shape[0]),"columns_count":int(df.shape[1])}
            if "label" in df.columns:
                data_info["label_counts"] = df["label"].fillna("Unknown").astype(str).value_counts().to_dict()
        except Exception:
            pass

    model_result = None
    if training_summary:
        try:
            fm   = training_summary.get("final_model", {})
            vals = training_summary.get("validation_results", {})

            algo_comparison = []
            for name, d in vals.items():
                algo_comparison.append({
                    "name":name,
                    "accuracy":      round(d.get("accuracy",0)*100, 2),
                    "precision":     round(d.get("precision_weighted",0)*100, 2),
                    "recall":        round(d.get("recall_weighted",0)*100, 2),
                    "f1":            round(d.get("f1_weighted",0)*100, 2),
                    "fpr":           round(d.get("false_positive_rate",0)*100, 2),
                    "detection_rate":round(d.get("detection_rate",0)*100, 2),
                })

            per_class_rows = []
            for cls_name, cls_data in fm.get("classification_report", {}).items():
                if cls_name in ("accuracy","macro avg","weighted avg"):
                    continue
                per_class_rows.append({
                    "label":cls_name,
                    "precision":round(cls_data.get("precision",0)*100, 2),
                    "recall":   round(cls_data.get("recall",0)*100, 2),
                    "f1":       round(cls_data.get("f1-score",0)*100, 2),
                    "support":  int(cls_data.get("support", 0)),
                })

            model_result = {
                "status":          "ok",
                "model_name":      fm.get("name","Soft Voting Ensemble"),
                "accuracy":        round(fm.get("test_accuracy",0)*100, 2),
                "precision":       round(fm.get("test_precision_weighted",0)*100, 2),
                "recall":          round(fm.get("test_recall_weighted",0)*100, 2),
                "f1":              round(fm.get("test_f1_weighted",0)*100, 2),
                "fpr":             round(fm.get("test_false_positive_rate",0)*100, 2),
                "detection_rate":  round(fm.get("test_detection_rate",0)*100, 2),
                "auc":             round(fm.get("test_auc_normal_vs_attack",0), 4),
                "cv_mean":         round(fm.get("cv_mean_accuracy",0)*100, 2),
                "cv_scores":       [round(s*100,2) for s in fm.get("cv_accuracy_scores",[])],
                "algo_comparison": algo_comparison,
                "per_class":       per_class_rows,
                "classes":         training_summary.get("classes",[]),
                "selected_k":      training_summary.get("selected_k_features",30),
                "best_val_model":  training_summary.get("best_validation_model",""),
            }
        except Exception as exc:
            model_result = {"status":"error","message":f"Could not parse training summary: {exc}"}

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) AS total FROM predictions")
        total_preds = int(c.fetchone()["total"])
        c.execute("SELECT COUNT(*) AS total FROM blocked_ips")
        total_blocked = int(c.fetchone()["total"])
        c.execute("SELECT prediction,COUNT(*) AS count FROM predictions GROUP BY prediction ORDER BY count DESC")
        pred_breakdown = [
            {"prediction":str(r["prediction"]),"display_prediction":to_display_label(str(r["prediction"])),"count":int(r["count"])}
            for r in c.fetchall()
        ]

    chart_bootstrap = {
        "hasModel": bool(model_result and model_result.get("status") == "ok"),
        "cvScores": (model_result or {}).get("cv_scores") or [],
        "perClass": (model_result or {}).get("per_class") or [],
        "algoComp": (model_result or {}).get("algo_comparison") or [],
        "predBreakdown": pred_breakdown or [],
        "metricsVersion": metrics_version,
        "familyColors": {
            (row.get("display_prediction") or row.get("prediction") or ""): family_chart_color(
                row.get("prediction") or row.get("display_prediction")
            )
            for row in (pred_breakdown or [])
        },
    }

    return {
        "data_info": data_info, "model_result": model_result,
        "training_summary": training_summary, "total_predictions": total_preds,
        "total_blocked": total_blocked, "pred_breakdown": pred_breakdown,
        "chart_bootstrap": chart_bootstrap, "metrics_version": metrics_version,
    }

# ── Helper: build recent_connections list from DB ──────────────────────────────
def fetch_recent_connections(limit=RECENT_CONNECTIONS_LIMIT):
    """
    Fetches the most recent N prediction records joined with live block status
    and the most recent feedback for each. Returns newest first.
    Called by both the /data route (server-render) and /api/recent-connections (JSON).
    """
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute(f"""
            SELECT p.id, p.timestamp, p.source_ip, p.prediction, p.confidence, p.is_unknown,
                   CASE WHEN b.source_ip IS NOT NULL THEN 1 ELSE 0 END AS is_blocked_live,
                   f.feedback_label, f.corrected_label, f.created_at AS feedback_time
            FROM predictions p
            LEFT JOIN blocked_ips b ON b.source_ip = p.source_ip
            LEFT JOIN feedback f ON f.id = (
                SELECT f2.id FROM feedback f2
                WHERE f2.prediction_id = p.id ORDER BY f2.id DESC LIMIT 1
            )
            ORDER BY p.id DESC LIMIT {int(limit)}
        """)
        rows = []
        for row in c.fetchall():
            pred = str(row["prediction"]); conf = float(row["confidence"]); iu = bool(row["is_unknown"])
            rl   = classify_risk_level(prediction=pred, confidence=conf, is_unknown=iu)
            dr   = build_decision_reason(prediction=pred, confidence=conf,
                                          risk_level=rl, is_unknown=iu, source_ip=row["source_ip"])
            rows.append({
                "id":int(row["id"]), "timestamp":fmt_dt(row["timestamp"]),
                "source_ip":row["source_ip"],
                "prediction":pred, "display_prediction":to_display_label(pred),
                "confidence":conf, "is_unknown":int(row["is_unknown"]),
                "is_blocked_ref":int(row["is_blocked_live"]),
                "feedback_label": None if row["feedback_label"] is None else str(row["feedback_label"]),
                "corrected_label":None if row["corrected_label"] is None else str(row["corrected_label"]),
                "feedback_time":fmt_dt(row["feedback_time"]),
                "risk_level":rl, "decision_reason":dr,
            })
        return rows

def fetch_stats():
    """Live stat-card values from the database."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) AS total FROM predictions")
        total = int(c.fetchone()["total"])
        c.execute("SELECT COUNT(*) AS total FROM blocked_ips")
        blocked = int(c.fetchone()["total"])
        c.execute("SELECT prediction,COUNT(*) AS count FROM predictions GROUP BY prediction ORDER BY count DESC")
        raw = [{"prediction":str(r["prediction"]),"count":int(r["count"])} for r in c.fetchall()]

    family = {}
    for row in raw:
        dp = to_display_label(row["prediction"])
        family[dp] = family.get(dp, 0) + int(row["count"])

    return {
        "total_connections": total,
        "total_blocked":     blocked,
        "attack_counts": [
            {"prediction":k,"display_prediction":k,"count":v}
            for k,v in sorted(family.items(), key=lambda x: x[1], reverse=True)
        ],
    }

# ── Routes — public pages ──────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/features")
def features():
    return render_template("features.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        access_key = request.form.get("access_key","").strip()
        expected   = os.environ.get("WAQQAS_ACCESS_KEY", "waqqas")
        if access_key == expected:
            session["logged_in"] = True
            return redirect(url_for("data"))
        flash("Incorrect access key. Verify your credentials and try again.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ── Routes — protected pages ───────────────────────────────────────────────────
@app.route("/analysis")
@login_required
def analysis():
    return render_template("analysis.html", **build_analysis_data())

@app.route("/api/analysis-summary", methods=["GET"])
@login_required
def api_analysis_summary():
    """JSON snapshot of analysis metrics — used to refresh the page after retraining."""
    payload = build_analysis_data()
    return jsonify({
        "metrics_version": payload.get("metrics_version", 0),
        "model_result": payload.get("model_result"),
        "total_predictions": payload.get("total_predictions", 0),
        "total_blocked": payload.get("total_blocked", 0),
        "pred_breakdown": payload.get("pred_breakdown", []),
        "chart_bootstrap": payload.get("chart_bootstrap", {}),
    }), 200

@app.route("/latest-upload-state", methods=["GET"])
def latest_upload_state():
    return jsonify(get_latest_upload_state()), 200

@app.route("/clear-pending-current-reasons", methods=["POST"])
def clear_pending_current_reasons():
    session["latest_upload_block_notes"] = []
    session.modified = True
    return jsonify({"message":"Pending current file reasons cleared."}), 200

@app.route("/dashboard")
@app.route("/data")
@login_required
def data():
    stats = fetch_stats()
    recent_connections = fetch_recent_connections()
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT source_ip,note_type,note_text,created_at FROM blocked_ip_notes ORDER BY id DESC LIMIT 50")
        block_notes = [{"source_ip":str(r["source_ip"]),"note_type":str(r["note_type"]),
                        "note_text":str(r["note_text"]),"created_at":fmt_dt(r["created_at"])}
                       for r in c.fetchall()]
    latest_state = get_latest_upload_state()
    return render_template("data.html",
        total_connections=stats["total_connections"],
        total_blocked=stats["total_blocked"],
        attack_counts=stats["attack_counts"],
        raw_attack_counts=stats["attack_counts"],
        recent_connections=recent_connections,
        block_notes=block_notes,
        latest_upload_results=latest_state["results"],
        latest_upload_alert_items=latest_state["alert_items"],
        latest_upload_block_notes=latest_state["block_notes"],
        latest_upload_threat_count=latest_state["threat_count"],
        active_dataset_filename=latest_state.get("active_filename", ""),
        saved_csv_files=list_saved_csv_files(),
    )

# ── API: live recent connections for JS table refresh ─────────────────────────
@app.route("/api/recent-connections", methods=["GET"])
def api_recent_connections():
    """
    Returns the latest N classified records as JSON.
    Called by the dashboard JS after each upload so the "Latest Classified
    Connections" table refreshes immediately without a full page reload.
    Newest records appear first (ORDER BY id DESC).
    """
    rows = fetch_recent_connections(limit=RECENT_CONNECTIONS_LIMIT)
    return jsonify({"connections": rows, "count": len(rows)}), 200

@app.route("/api/stats-live", methods=["GET"])
def api_stats_live():
    """Live stat-card values — called by JS after upload to update counters."""
    return jsonify(fetch_stats()), 200

# ── Routes — predict ───────────────────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
@login_required
def predict():
    global model, label_encoder
    if model is None or label_encoder is None:
        return jsonify({"error":"Model artifacts are not loaded."}), 500
    try:
        if "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                return jsonify({"error_type":"no_file","error":"No file selected.","message":"Choose a CSV file before running detection."}), 400
            if not allowed_file(file.filename):
                return jsonify({"error_type":"invalid_extension","error":"Only CSV files are allowed.","message":"Upload a .csv file."}), 400
            hc = validate_csv_headers_before_read(file)
            if not hc["ok"]:
                return jsonify(hc["response"]), 400
            sp = UPLOADS_DIR / secure_filename(file.filename)
            file.save(sp)
            try:
                df = pd.read_csv(sp)
            except EmptyDataError:
                return jsonify({"error_type":"empty_file","error":"The uploaded CSV is empty."}), 400
            except ParserError:
                return jsonify({"error_type":"parser_error","error":"The CSV could not be parsed."}), 400
            pp = predict_dataframe(df)
            saved_name = sp.name
            store_latest_upload_state(pp, filename=saved_name)
            ep = session.get("latest_upload_block_notes", [])
            if pp["block_notes"]:
                session["latest_upload_block_notes"] = trim_list(pp["block_notes"] + ep, MAX_LATEST_NOTES)
                session.modified = True
            return jsonify({
                "input_type":"csv","saved_filename":saved_name,"rows_processed":len(pp["results"]),
                "results":pp["results"],"alert_items":pp["alert_items"],
                "block_notes":session.get("latest_upload_block_notes",[]),
                "block_notes_new":pp["block_notes"],
                "threat_count":pp["threat_count"],"family_counts":pp["family_counts"],
            }), 200

        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error_type":"missing_input","error":"Request must contain CSV file or JSON body."}), 400
        if isinstance(payload, dict):   df = pd.DataFrame([payload])
        elif isinstance(payload, list): df = pd.DataFrame(payload)
        else:
            return jsonify({"error_type":"invalid_json","error":"JSON payload must be an object or list."}), 400
        pp = predict_dataframe(df)
        store_latest_upload_state(pp)
        ep = session.get("latest_upload_block_notes", [])
        if pp["block_notes"]:
            session["latest_upload_block_notes"] = trim_list(pp["block_notes"] + ep, MAX_LATEST_NOTES)
            session.modified = True
        return jsonify({
            "input_type":"json","rows_processed":len(pp["results"]),
            "results":pp["results"],"alert_items":pp["alert_items"],
            "block_notes":session.get("latest_upload_block_notes",[]),
            "block_notes_new":pp["block_notes"],
            "threat_count":pp["threat_count"],"family_counts":pp["family_counts"],
        }), 200

    except ValueError as exc:
        try:    return jsonify(json.loads(str(exc))), 400
        except: return jsonify({"error_type":"validation_error","error":str(exc),"message":"Validation failed."}), 400
    except Exception as exc:
        return jsonify({"error_type":"server_error","error":f"Prediction failed: {str(exc)}","message":"An unexpected error occurred."}), 500

@app.route("/predict-saved", methods=["POST"])
@login_required
def predict_saved():
    """
    Re-run the full prediction pipeline on a CSV that already exists under uploads/.
    Used by the dashboard 'recent datasets' picker so analysts can re-classify
    without re-uploading the binary from their machine.
    """
    global model, label_encoder
    if model is None or label_encoder is None:
        return jsonify({"error":"Model artifacts are not loaded."}), 500
    d = request.get_json(silent=True) or {}
    raw = str(d.get("filename", "") or d.get("name", "")).strip()
    if not raw:
        return jsonify({"error_type":"missing_filename","error":"filename is required.",
                        "message":"Select a dataset from recent history or upload a new file."}), 400
    safe = secure_filename(os.path.basename(raw))
    if not safe.lower().endswith(".csv"):
        return jsonify({"error_type":"invalid_extension","error":"Only CSV files are allowed.",
                        "message":"Choose a valid .csv dataset name."}), 400
    path = (UPLOADS_DIR / safe).resolve()
    try:
        uploads_root = UPLOADS_DIR.resolve()
        if not str(path).startswith(str(uploads_root)) or not path.is_file():
            return jsonify({"error_type":"not_found","error":"File not found.",
                            "message":"That dataset is no longer on the server. Upload it again."}), 404
    except OSError:
        return jsonify({"error_type":"not_found","error":"File not found.",
                        "message":"That dataset is no longer on the server. Upload it again."}), 404
    try:
        with open(path, "rb") as fh:
            fs = FileStorage(stream=fh, filename=safe)
            hc = validate_csv_headers_before_read(fs)
        if not hc["ok"]:
            return jsonify(hc["response"]), 400
        df = pd.read_csv(path)
    except EmptyDataError:
        return jsonify({"error_type":"empty_file","error":"The saved CSV is empty."}), 400
    except ParserError:
        return jsonify({"error_type":"parser_error","error":"The CSV could not be parsed."}), 400
    try:
        pp = predict_dataframe(df)
        store_latest_upload_state(pp, filename=safe)
        ep = session.get("latest_upload_block_notes", [])
        if pp["block_notes"]:
            session["latest_upload_block_notes"] = trim_list(pp["block_notes"] + ep, MAX_LATEST_NOTES)
            session.modified = True
        return jsonify({
            "input_type":"saved_csv","saved_filename":safe,"rows_processed":len(pp["results"]),
            "results":pp["results"],"alert_items":pp["alert_items"],
            "block_notes":session.get("latest_upload_block_notes",[]),
            "block_notes_new":pp["block_notes"],
            "threat_count":pp["threat_count"],"family_counts":pp["family_counts"],
        }), 200
    except ValueError as exc:
        try:
            return jsonify(json.loads(str(exc))), 400
        except Exception:
            return jsonify({"error_type":"validation_error","error":str(exc),"message":"Validation failed."}), 400
    except Exception as exc:
        return jsonify({"error_type":"server_error","error":f"Prediction failed: {str(exc)}",
                        "message":"An unexpected error occurred."}), 500

# ── Routes — block / unblock ───────────────────────────────────────────────────
@app.route("/block-ip", methods=["POST"])
def block_ip():
    d = request.get_json(silent=True) or {}
    source_ip  = d.get("source_ip")
    prediction = d.get("prediction","Suspicious Activity")
    confidence = float(d.get("confidence", 0.0))
    reason     = d.get("reason") or create_block_note_text(source_ip, prediction, confidence, mode="manual")
    if not source_ip:
        return jsonify({"error":"source_ip is required."}), 400
    note = auto_block_ip(source_ip, reason)
    append_pending_note_to_session(note)
    return jsonify({"message":"IP blocked successfully.","source_ip":str(source_ip),"note":note}), 200

@app.route("/unblock-ip", methods=["POST"])
def unblock_ip():
    d = request.get_json(silent=True) or {}
    source_ip = d.get("source_ip"); reason = d.get("reason")
    if not source_ip or not reason:
        return jsonify({"error":"source_ip and reason are required."}), 400
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ips WHERE source_ip=?", (str(source_ip),))
        c.execute("INSERT INTO blocked_ip_notes (source_ip,note_type,note_text,created_at) VALUES (?,?,?,?)",
                  (str(source_ip),"unblock",str(reason),now_str()))
        c.execute("UPDATE predictions SET is_blocked_ref=0 WHERE source_ip=?", (str(source_ip),))
        conn.commit()
    note = {"source_ip":str(source_ip),"note_type":"unblock","note_text":str(reason),"created_at":fmt_dt(now_str())}
    append_pending_note_to_session(note)
    return jsonify({"message":"IP unblocked successfully.","source_ip":str(source_ip),"note":note}), 200

# ── Routes — feedback ──────────────────────────────────────────────────────────
@app.route("/feedback", methods=["POST"])
def add_feedback():
    """
    Records analyst feedback. The corrected_label is normalized via the
    LABEL_ALIASES map before storage so the retraining pipeline always
    receives canonical labels regardless of how the analyst typed them.
    Ambiguous entries are rejected with a label_warning response.
    """
    d = request.get_json(silent=True) or {}
    prediction_id  = d.get("prediction_id")
    feedback_label = str(d.get("feedback_label","")).strip().lower()
    raw_corrected  = d.get("corrected_label")

    if not prediction_id or not feedback_label:
        return jsonify({"error":"prediction_id and feedback_label are required."}), 400
    if feedback_label not in VALID_FEEDBACK_LABELS:
        return jsonify({"error":"Invalid feedback_label.","allowed_values":sorted(VALID_FEEDBACK_LABELS)}), 400

    canonical_corrected = None
    if raw_corrected:
        canonical_corrected = resolve_canonical_label(str(raw_corrected), allow_unknown=True)
        if canonical_corrected is None:
            return jsonify({
                "error":"label_ambiguous","label_warning":True,
                "message":f"The label '{raw_corrected}' could not be mapped. Use: Normal, DoS, Probe, U2R, R2L, or Unknown Suspicious Behavior.",
                "allowed_labels":list(CANONICAL_LABELS) + ["Unknown Suspicious Behavior"],
            }), 400

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM predictions WHERE id=?", (int(prediction_id),))
        if c.fetchone() is None:
            return jsonify({"error":"prediction_id does not exist."}), 404
        c.execute("INSERT INTO feedback (prediction_id,feedback_label,corrected_label,created_at) VALUES (?,?,?,?)",
                  (int(prediction_id),str(feedback_label),
                   None if canonical_corrected is None else str(canonical_corrected), now_str()))
        conn.commit()
    return jsonify({"message":"Feedback saved.","prediction_id":int(prediction_id),
                    "canonical_label":canonical_corrected}), 200

# ── Routes — stats / block notes ───────────────────────────────────────────────
@app.route("/stats", methods=["GET"])
def stats():
    s = fetch_stats()
    return jsonify({
        "total_predictions":s["total_connections"],"total_blocked_ips":s["total_blocked"],
        "family_prediction_breakdown":s["attack_counts"],
    }), 200

@app.route("/block-notes", methods=["GET"])
def get_block_notes():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT source_ip,note_type,note_text,created_at FROM blocked_ip_notes ORDER BY id DESC LIMIT 100")
        notes = [{"source_ip":str(r["source_ip"]),"note_type":str(r["note_type"]),
                  "note_text":str(r["note_text"]),"created_at":fmt_dt(r["created_at"])}
                 for r in c.fetchall()]
    return jsonify({"notes":notes}), 200

@app.route("/clear-block-notes", methods=["POST"])
def clear_block_notes():
    """Archive active notes to history, then clear the live list (spec G)."""
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""INSERT INTO blocked_ip_notes_history
            (source_ip,note_type,note_text,original_created_at,archived_at)
            SELECT source_ip,note_type,note_text,created_at,? FROM blocked_ip_notes""",
            (now_str(),))
        c.execute("DELETE FROM blocked_ip_notes")
        try: c.execute("DELETE FROM sqlite_sequence WHERE name='blocked_ip_notes'")
        except: pass
        conn.commit()
    session["latest_upload_block_notes"] = []
    session.modified = True
    return jsonify({"message":"Active block notes cleared and archived to history."}), 200

@app.route("/block-notes-history", methods=["GET"])
def get_block_notes_history():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""SELECT source_ip,note_type,note_text,original_created_at,archived_at
            FROM blocked_ip_notes_history ORDER BY id DESC LIMIT 200""")
        notes = [{"source_ip":str(r["source_ip"]),"note_type":str(r["note_type"]),
                  "note_text":str(r["note_text"]),"created_at":fmt_dt(r["original_created_at"]),
                  "archived_at":fmt_dt(r["archived_at"])} for r in c.fetchall()]
    return jsonify({"notes":notes,"count":len(notes)}), 200

@app.route("/delete-block-notes-history", methods=["POST"])
def delete_block_notes_history():
    d = request.get_json(silent=True) or {}
    if str(d.get("admin_password","")).strip() != "waqqas-admin":
        return jsonify({"error":"Invalid admin password. History was not deleted."}), 403
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ip_notes_history")
        try: c.execute("DELETE FROM sqlite_sequence WHERE name='blocked_ip_notes_history'")
        except: pass
        conn.commit()
    return jsonify({"message":"Block notes history deleted."}), 200

@app.route("/reset-block-notes", methods=["POST"])
def reset_block_notes():
    d = request.get_json(silent=True) or {}
    if str(d.get("admin_password","")).strip() != "waqqas-admin":
        return jsonify({"error":"Invalid admin password."}), 403
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM blocked_ip_notes")
        try: c.execute("DELETE FROM sqlite_sequence WHERE name='blocked_ip_notes'")
        except: pass
        conn.commit()
    session["latest_upload_block_notes"] = []
    session.modified = True
    return jsonify({"message":"Block / unblock reasons log was reset."}), 200

@app.route("/reset-recent-connections", methods=["POST"])
def reset_recent_connections():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM feedback")
        c.execute("DELETE FROM predictions")
        for t in ("feedback","predictions"):
            try: c.execute(f"DELETE FROM sqlite_sequence WHERE name='{t}'")
            except: pass
        conn.commit()
    clear_latest_upload_state()
    return jsonify({"message":"Records cleared.","cards":{"total_connections":0,"attack_types":0},"prediction_breakdown":[]}), 200

# ── Routes — retraining ────────────────────────────────────────────────────────
def _training_subprocess_env():
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def _resolve_training_python():
    """Pick an interpreter that can import project training dependencies."""
    import subprocess

    candidates = []
    venv_py = BASE_DIR / ".venv" / "Scripts" / "python.exe"
    if venv_py.is_file():
        candidates.append(str(venv_py))
    if sys.executable:
        candidates.append(sys.executable)
    for name in ("python", "py"):
        candidates.append(name)

    seen = set()
    for py in candidates:
        if not py or py in seen:
            continue
        seen.add(py)
        try:
            probe = subprocess.run(
                [py, "-c", "import sklearn, imblearn, pandas, joblib"],
                cwd=str(BASE_DIR),
                capture_output=True,
                text=True,
                timeout=30,
                env=_training_subprocess_env(),
            )
            if probe.returncode == 0:
                return py
        except Exception:
            continue
    return sys.executable


def _run_retrain_async():
    """
    Background thread: runs train_models.py as a subprocess.

    DATA SOURCE FOR RETRAINING:
    - The script reads data/KDDTrain+.TXT and data/KDDTest+.TXT (NSL-KDD benchmark).
    - It does NOT read uploaded CSV files, the SQLite database, analyst feedback,
      or any data from the uploads/ directory.
    - Analyst feedback is exported separately via /export-feedback-csv and can be
      manually incorporated into training data, but this is not done automatically.

    WHY NSL-KDD ONLY:
    - NSL-KDD is a labeled benchmark dataset with verified ground truth.
    - Feedback records are too small and potentially noisy for full model retraining.
    - The "70 devices" seen in the terminal during retraining is the full NSL-KDD
      training pipeline — not related to the 10 records in the uploaded traffic file.

    WHAT THIS PRODUCES:
    - Updated models/ids_model.joblib and models/label_encoder.joblib
    - Updated reports/training_summary.json (full metrics for Analysis page)
    - The live model is hot-reloaded in memory after training completes.
    """
    global _retrain_status, model, label_encoder
    import subprocess
    import time

    train_script = BASE_DIR / "train_models.py"
    train_python = _resolve_training_python()
    if not train_script.exists():
        with _retrain_lock:
            _retrain_status.update({"running":False,"last_error":"Training script not found."})
        return

    start = time.time()
    try:
        result = subprocess.run(
            [train_python, str(train_script)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=3600,
            env=_training_subprocess_env(),
        )
        duration = round(time.time() - start, 1)
        with _retrain_lock:
            _retrain_status["running"] = False
            if result.returncode == 0:
                metrics_version = 0
                ts_path = REPORTS_DIR / "training_summary.json"
                if ts_path.exists():
                    try:
                        metrics_version = int(ts_path.stat().st_mtime)
                    except OSError:
                        pass
                _retrain_status["last_result"] = {
                    "status":"ok","duration_seconds":duration,
                    "message":"Retraining completed. Model reloaded. Open Analysis to see updated metrics.",
                    "metrics_version":metrics_version,
                    "stdout_tail":result.stdout.strip()[-2000:],
                }
                _retrain_status["last_error"] = None
                # Hot-reload model artifacts so the live system uses the new weights immediately
                try:
                    nm, nle = load_artifacts()
                    model = nm; label_encoder = nle
                except Exception as e:
                    _retrain_status["last_error"] = f"Training succeeded but model reload failed: {e}"
            else:
                err_parts = [f"Training script exited with code {result.returncode}."]
                stderr_tail = (result.stderr or "").strip()
                stdout_tail = (result.stdout or "").strip()
                if stderr_tail:
                    err_parts.append("STDERR (last 2000 chars):\n" + stderr_tail[-2000:])
                if stdout_tail:
                    err_parts.append("STDOUT (last 1200 chars):\n" + stdout_tail[-1200:])
                if not stderr_tail and not stdout_tail:
                    err_parts.append("No output captured. Check that the project virtual environment has all dependencies installed.")
                _retrain_status.update({"last_result": None, "last_error": "\n\n".join(err_parts)})
    except subprocess.TimeoutExpired:
        with _retrain_lock:
            _retrain_status.update({"running":False,"last_error":"Training timed out after 3600s."})
    except Exception as exc:
        with _retrain_lock:
            _retrain_status.update({"running":False,"last_error":f"Training failed: {exc}"})

@app.route("/retrain", methods=["POST"])
def retrain():
    """
    Trigger async model retraining using the NSL-KDD dataset.
    Returns immediately (HTTP 202). Poll /retrain-status for progress.
    After completion, reload /analysis to see updated metrics.
    """
    global _retrain_status
    with _retrain_lock:
        if _retrain_status["running"]:
            return jsonify({"status":"already_running","message":"A retraining job is already in progress."}), 409
        _retrain_status.update({"running":True,"last_error":None})
    threading.Thread(target=_run_retrain_async, daemon=True).start()
    return jsonify({"status":"started","message":"Retraining started. Poll /retrain-status for progress."}), 202

@app.route("/retrain-status", methods=["GET"])
def retrain_status():
    with _retrain_lock:
        return jsonify(dict(_retrain_status)), 200

@app.route("/export-feedback-csv", methods=["GET"])
def export_feedback_csv():
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("""SELECT p.timestamp,p.source_ip,p.prediction,p.confidence,
            f.feedback_label,f.corrected_label,f.created_at AS feedback_time
            FROM feedback f JOIN predictions p ON p.id=f.prediction_id ORDER BY f.id DESC""")
        rows = c.fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp","source_ip","original_prediction","confidence",
                     "feedback_label","corrected_label","feedback_time"])
    for r in rows:
        writer.writerow([r["timestamp"],r["source_ip"],r["prediction"],r["confidence"],
                         r["feedback_label"],r["corrected_label"],r["feedback_time"]])
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment; filename=waqqas_feedback_export.csv"})

# ── Bootstrap (lazy — avoids double model load under debug reloader / slow IDE start) ──
def ensure_bootstrapped():
    global model, label_encoder, _bootstrap_done
    if _bootstrap_done:
        return
    ensure_dirs()
    init_db()
    if model is None or label_encoder is None:
        model, label_encoder = load_artifacts()
    _bootstrap_done = True


@app.before_request
def _bootstrap_on_request():
    if request.endpoint == "static":
        return
    ensure_bootstrapped()


if __name__ == "__main__":
    ensure_bootstrapped()
    debug = os.environ.get("FLASK_DEBUG", "1").strip().lower() in ("1", "true", "yes")
    # Reloader spawns a second process and loads the ML model twice — very slow in VS Code.
    use_reloader = os.environ.get("FLASK_USE_RELOADER", "0").strip().lower() in ("1", "true", "yes")
    app.run(debug=debug, use_reloader=use_reloader)
