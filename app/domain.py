import ipaddress
import json
import ntpath
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit

VERDICT_RANK = {"failed": -1, "unknown": 0, "benign": 1, "suspicious": 2, "malicious": 3}


def normalize_verdict(value, failed=False):
    if failed:
        return "failed"
    text = str(value or "").strip().lower()
    if text in VERDICT_RANK:
        return text
    if text in {"clean", "not_suspicious"}:
        return "benign"
    return "unknown"


def normalize_ioc(kind, value):
    original = unicodedata.normalize("NFKC", str(value)).strip()
    kind = kind.lower().replace("-", "")
    if kind in {"md5", "sha1", "sha256"}:
        lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        lowered = original.lower()
        return lowered if len(lowered) == lengths[kind] and re.fullmatch(r"[0-9a-f]+", lowered) else original
    if kind in {"ipv4", "ipv6", "ip"}:
        try: return ipaddress.ip_address(original).compressed.lower()
        except ValueError: return original.lower()
    if kind in {"domain", "hostname"}:
        return original.rstrip(".").lower().encode("idna").decode("ascii")
    if kind in {"email", "emailaddress"} and "@" in original:
        local, domain = original.rsplit("@", 1)
        return f"{local}@{domain.rstrip('.').lower().encode('idna').decode('ascii')}"
    if kind == "url":
        try:
            parts = urlsplit(original)
            host = (parts.hostname or "").lower().encode("idna").decode("ascii")
            port = parts.port
            netloc = host + ((f":{port}") if port and not (parts.scheme.lower()=="http" and port==80) and not (parts.scheme.lower()=="https" and port==443) else "")
            return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment))
        except ValueError: return original
    if kind in {"windowspath", "path"}:
        return ntpath.normpath(original.replace("/", "\\")).lower()
    if kind == "filename":
        return original.lower()
    return original


def vti_key(item):
    return str(item.get("id") or item.get("stable_id")), item.get("scope", "analysis"), str(item.get("artifact_id") or "")


def compare_vtis(before, after):
    left, right = {vti_key(x): x for x in before}, {vti_key(x): x for x in after}
    return {
        "added": [right[k] for k in right.keys() - left.keys()],
        "removed": [left[k] for k in left.keys() - right.keys()],
        "score_increased": [(left[k], right[k]) for k in left.keys() & right.keys() if (right[k].get("score") or 0) > (left[k].get("score") or 0)],
        "score_decreased": [(left[k], right[k]) for k in left.keys() & right.keys() if (right[k].get("score") or 0) < (left[k].get("score") or 0)],
    }
