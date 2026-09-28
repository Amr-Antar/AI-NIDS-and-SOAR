from __future__ import annotations

from typing import Optional

CANONICAL_LABELS = ["Normal", "DoS", "Probe", "U2R", "R2L"]

DISPLAY_LABELS = {
    "Normal": "Normal Traffic",
    "DoS": "Denial of Service",
    "Probe": "Reconnaissance / Scanning",
    "U2R": "Privilege Escalation",
    "R2L": "Credential / Access Abuse",
    "Unknown Suspicious Behavior": "Unknown Suspicious Behavior",
}

# Unique professional palette — one color per attack family (dark cybersecurity theme).
FAMILY_CHART_COLORS = {
    "Normal": "#1fd1a5",
    "DoS": "#e06a76",
    "Probe": "#f2c46d",
    "U2R": "#a88cff",
    "R2L": "#39cfff",
    "Unknown Suspicious Behavior": "#ff9b6b",
}

FAMILY_CSS_CLASSES = {
    "Normal": "breakdown-fam-normal",
    "DoS": "breakdown-fam-dos",
    "Probe": "breakdown-fam-probe",
    "U2R": "breakdown-fam-u2r",
    "R2L": "breakdown-fam-r2l",
    "Unknown Suspicious Behavior": "breakdown-fam-unknown",
}

LABEL_ALIASES = {
    "normal": "Normal",
    "normal traffic": "Normal",
    "benign": "Normal",
    "safe": "Normal",
    "legitimate": "Normal",
    "clean": "Normal",
    "dos": "DoS",
    "denial of service": "DoS",
    "ddos": "DoS",
    "probe": "Probe",
    "recon": "Probe",
    "reconnaissance": "Probe",
    "reconnaissance / scanning": "Probe",
    "scan": "Probe",
    "scanning": "Probe",
    "u2r": "U2R",
    "privilege escalation": "U2R",
    "user to root": "U2R",
    "r2l": "R2L",
    "credential / access abuse": "R2L",
    "credential abuse": "R2L",
    "remote to local": "R2L",
    "unknown suspicious behavior": "Unknown Suspicious Behavior",
    "unknown": "Unknown Suspicious Behavior",
    "suspicious": "Unknown Suspicious Behavior",
}

NSL_ATTACK_CATEGORY_MAP = {
    "normal": "Normal",
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS", "teardrop": "DoS",
    "apache2": "DoS", "mailbomb": "DoS", "processtable": "DoS", "udpstorm": "DoS", "worm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L", "phf": "R2L", "spy": "R2L",
    "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L",
    "snmpguess": "R2L", "xlock": "R2L", "xsnoop": "R2L", "httptunnel": "R2L",
}

CRITICAL_LABELS = {"DoS", "U2R"}
DANGER_LABELS = {"Probe", "R2L"}

_DISPLAY_TO_CANONICAL = {v.lower(): k for k, v in DISPLAY_LABELS.items()}


def normalize_label_text(value: Optional[str]) -> str:
    return str(value or "").strip()


def resolve_canonical_label(value: Optional[str], allow_unknown: bool = True) -> Optional[str]:
    text = normalize_label_text(value)
    if not text:
        return None
    if text in CANONICAL_LABELS:
        return text
    lowered = text.lower()
    if lowered in LABEL_ALIASES:
        resolved = LABEL_ALIASES[lowered]
        if resolved == "Unknown Suspicious Behavior" and not allow_unknown:
            return None
        return resolved
    if lowered in _DISPLAY_TO_CANONICAL:
        return _DISPLAY_TO_CANONICAL[lowered]
    return None


def to_display_label(value: Optional[str]) -> str:
    canonical = resolve_canonical_label(value, allow_unknown=True)
    if canonical is None:
        canonical = normalize_label_text(value) or "Unknown Suspicious Behavior"
    return DISPLAY_LABELS.get(canonical, canonical)


def breakdown_family_css_class(label: Optional[str]) -> str:
    """Return a unique CSS class for each attack family row/chart segment."""
    canonical = resolve_canonical_label(label, allow_unknown=True)
    if canonical and canonical in FAMILY_CSS_CLASSES:
        return FAMILY_CSS_CLASSES[canonical]
    return FAMILY_CSS_CLASSES["Unknown Suspicious Behavior"]


def family_chart_color(label: Optional[str]) -> str:
    """Return a unique chart color for each attack family."""
    canonical = resolve_canonical_label(label, allow_unknown=True)
    if canonical and canonical in FAMILY_CHART_COLORS:
        return FAMILY_CHART_COLORS[canonical]
    return FAMILY_CHART_COLORS["Unknown Suspicious Behavior"]


def map_attack_name_to_canonical(name: Optional[str]) -> str:
    lowered = normalize_label_text(name).lower()
    return NSL_ATTACK_CATEGORY_MAP.get(lowered, "Unknown")


def classify_risk_level(label: Optional[str], confidence: float, is_unknown: bool) -> str:
    canonical = resolve_canonical_label(label, allow_unknown=True)
    if is_unknown or canonical == "Unknown Suspicious Behavior":
        return "unknown"
    if canonical == "Normal":
        return "safe"
    if canonical in CRITICAL_LABELS:
        return "critical" if confidence >= 0.85 else "danger"
    if canonical in DANGER_LABELS:
        return "danger"
    return "safe"


def feedback_helper_examples() -> str:
    return "Examples: Normal, DoS, Probe, U2R, R2L, Denial of Service, Reconnaissance, Privilege Escalation"
