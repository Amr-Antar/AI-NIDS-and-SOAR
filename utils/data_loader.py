<<<<<<< HEAD
from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError, ParserError


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"

SOURCE_IP_COLUMN = "source_ip"

REQUIRED_FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

REQUIRED_COLUMNS_FOR_PREDICTION = REQUIRED_FEATURE_COLUMNS + [SOURCE_IP_COLUMN]

OPTIONAL_LABEL_COLUMN = "label"
VALID_RETRAIN_LABELS = {"Normal", "DoS", "Probe", "U2R", "R2L"}


def ensure_uploads_dir():
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def normalize_columns(columns):
    return [str(column).strip() for column in columns]


def load_csv_file(file_path) -> pd.DataFrame:
    try:
        df = pd.read_csv(file_path)
    except EmptyDataError:
        raise ValueError("The CSV file is empty.")
    except ParserError:
        raise ValueError("The CSV file could not be parsed.")
    except Exception as exc:
        raise ValueError(f"Failed to read CSV file: {exc}")

    if df.empty:
        raise ValueError("The CSV file contains no data rows.")

    df.columns = normalize_columns(df.columns)
    return df


def validate_prediction_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = normalize_columns(df.columns)

    missing_columns = [col for col in REQUIRED_FEATURE_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Missing required feature columns: {', '.join(missing_columns)}"
        )

    if SOURCE_IP_COLUMN not in df.columns:
        df[SOURCE_IP_COLUMN] = None

    return df[REQUIRED_COLUMNS_FOR_PREDICTION].copy()


def validate_retrain_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = normalize_columns(df.columns)

    required_columns = REQUIRED_FEATURE_COLUMNS + [OPTIONAL_LABEL_COLUMN]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Missing retrain columns: {', '.join(missing_columns)}"
        )

    df[OPTIONAL_LABEL_COLUMN] = df[OPTIONAL_LABEL_COLUMN].astype(str).str.strip()

    invalid_labels = sorted(
        set(df[OPTIONAL_LABEL_COLUMN].dropna().unique()) - VALID_RETRAIN_LABELS
    )
    if invalid_labels:
        raise ValueError(
            f"Invalid retrain labels found: {', '.join(invalid_labels)}"
        )

    return df[required_columns].copy()


def get_dataframe_info(df: pd.DataFrame) -> dict:
    preview_df = df.head().fillna("").astype(str)

    info = {
        "rows": int(df.shape[0]),
        "columns_count": int(df.shape[1]),
        "columns": list(df.columns),
        "preview_rows": preview_df.values.tolist(),
    }

    if OPTIONAL_LABEL_COLUMN in df.columns:
        label_counts = (
            df[OPTIONAL_LABEL_COLUMN]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .to_dict()
        )
        info["label_counts"] = label_counts

=======
from pathlib import Path

import pandas as pd
from pandas.errors import EmptyDataError, ParserError


BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"

SOURCE_IP_COLUMN = "source_ip"

REQUIRED_FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

REQUIRED_COLUMNS_FOR_PREDICTION = REQUIRED_FEATURE_COLUMNS + [SOURCE_IP_COLUMN]

OPTIONAL_LABEL_COLUMN = "label"
VALID_RETRAIN_LABELS = {"Normal", "DoS", "Probe", "U2R", "R2L"}


def ensure_uploads_dir():
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def normalize_columns(columns):
    return [str(column).strip() for column in columns]


def load_csv_file(file_path) -> pd.DataFrame:
    try:
        df = pd.read_csv(file_path)
    except EmptyDataError:
        raise ValueError("The CSV file is empty.")
    except ParserError:
        raise ValueError("The CSV file could not be parsed.")
    except Exception as exc:
        raise ValueError(f"Failed to read CSV file: {exc}")

    if df.empty:
        raise ValueError("The CSV file contains no data rows.")

    df.columns = normalize_columns(df.columns)
    return df


def validate_prediction_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = normalize_columns(df.columns)

    missing_columns = [col for col in REQUIRED_FEATURE_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Missing required feature columns: {', '.join(missing_columns)}"
        )

    if SOURCE_IP_COLUMN not in df.columns:
        df[SOURCE_IP_COLUMN] = None

    return df[REQUIRED_COLUMNS_FOR_PREDICTION].copy()


def validate_retrain_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = normalize_columns(df.columns)

    required_columns = REQUIRED_FEATURE_COLUMNS + [OPTIONAL_LABEL_COLUMN]
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Missing retrain columns: {', '.join(missing_columns)}"
        )

    df[OPTIONAL_LABEL_COLUMN] = df[OPTIONAL_LABEL_COLUMN].astype(str).str.strip()

    invalid_labels = sorted(
        set(df[OPTIONAL_LABEL_COLUMN].dropna().unique()) - VALID_RETRAIN_LABELS
    )
    if invalid_labels:
        raise ValueError(
            f"Invalid retrain labels found: {', '.join(invalid_labels)}"
        )

    return df[required_columns].copy()


def get_dataframe_info(df: pd.DataFrame) -> dict:
    preview_df = df.head().fillna("").astype(str)

    info = {
        "rows": int(df.shape[0]),
        "columns_count": int(df.shape[1]),
        "columns": list(df.columns),
        "preview_rows": preview_df.values.tolist(),
    }

    if OPTIONAL_LABEL_COLUMN in df.columns:
        label_counts = (
            df[OPTIONAL_LABEL_COLUMN]
            .fillna("Unknown")
            .astype(str)
            .value_counts()
            .to_dict()
        )
        info["label_counts"] = label_counts

>>>>>>> 38bc9e24b3d6457bccd27731a1e182084f56adda
    return info