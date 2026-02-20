#!/usr/bin/env python3
"""
Cisco ISE - Check System Certificate Expiration for Admin & EAP services (multi-node)

- Reads hosts from ise_hosts.txt (supports # comments/blank lines)
- Prompts for ERS creds
- Logs to ise_cert_check.log and writes ise_cert_check_summary.txt
- Robust matching of "Admin" and "EAP Authentication" service bindings
- Paged retrieval of system certificates (size=100, page=1..N)
- Optional --debug flag to log raw usage fields & normalized tokens
"""
import argparse
import datetime
import getpass
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOSTS_FILE   = "ise_hosts.txt"
LOG_FILE     = "ise_cert_check.log"
SUMMARY_FILE = "ise_cert_check_summary.txt"
PORT         = 9060
TIMEOUT_SEC  = 20
PAGE_SIZE    = 100  # ISE requires 1..100

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

USAGE_ADMIN = "ADMIN"
USAGE_EAP   = "EAPAuthentication"

# ---------- generic helpers ----------

def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_event(message: str) -> None:
    entry = f"[{now_ts()}] {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry, flush=True)

def load_hosts(file_path: str) -> List[str]:
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")
    hosts: List[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if line:
            hosts.append(line)
    return list(dict.fromkeys(hosts))

def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}

def format_error_detail(resp: requests.Response) -> str:
    j = safe_json(resp)
    if j:
        try:
            return f"HTTP {resp.status_code} - {json.dumps(j, ensure_ascii=False)}"
        except Exception:
            pass
    txt = (resp.text or "").strip()
    if txt:
        if len(txt) > 600:
            txt = txt[:600] + "...(truncated)"
        return f"HTTP {resp.status_code} - {txt}"
    return f"HTTP {resp.status_code} - No response body"

def parse_iso_datetime(dt_str: str) -> Optional[datetime.datetime]:
    if not dt_str:
        return None
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%b %d, %Y %I:%M:%S %p",
        "%d %b %Y %H:%M:%S",
    ]
    for fmt in fmts:
        try:
            return datetime.datetime.strptime(dt_str, fmt)
        except Exception:
            continue
    return None

def days_remaining(exp: Optional[datetime.datetime]) -> Optional[int]:
    if not exp:
        return None
    now = datetime.datetime.utcnow()
    return (exp - now).days

# ---------- ERS calls (with pagination) ----------

def _fetch_page(session: requests.Session, base: str, page: int) -> Tuple[Optional[List[dict]], Optional[List[dict]], str]:
    """
    Returns (resource_refs, full_list, reason)
      - resource_refs: list of objects under SearchResult.resources (ids/links) when ERS returns references
      - full_list:     list of full certificate objects when ERS returns them directly
    """
    url = f"{base}/ers/config/systemcertificate?size={PAGE_SIZE}&page={page}"
    r = session.get(url, timeout=TIMEOUT_SEC)
    if r.status_code != 200:
        return None, None, format_error_detail(r)

    body = safe_json(r)

    # Common: references under SearchResult.resources
    if "SearchResult" in body and "resources" in body["SearchResult"]:
        resources = body["SearchResult"]["resources"] or []
        return resources, None, "OK"

    # Some builds return full lists directly
    possible_lists = [
        body.get("ERSSystemCertificateList"),
        body.get("SystemCertificateList"),
        body.get("SystemCertificate"),
        body.get("ERSSystemCertificate"),
        body.get("response"),
        body.get("items"),
    ]
    for lst in possible_lists:
        if isinstance(lst, list):
            return None, lst, "OK"

    # Single object fallback
    if any(k in body for k in ("ERSSystemCertificate", "SystemCertificate", "friendlyName", "usage", "services")):
        return None, [body], "OK"

    return None, None, "Unexpected payload (no resources or list found)"

def _fetch_cert_by_id(session: requests.Session, base: str, cid: str) -> Optional[dict]:
    rc = session.get(f"{base}/ers/config/systemcertificate/{cid}", timeout=TIMEOUT_SEC)
    if rc.status_code != 200:
        log_event(f"INFO: {base} - could not fetch certificate {cid}: {format_error_detail(rc)}")
        return None
    detail = safe_json(rc)
    return detail.get("ERSSystemCertificate") or detail.get("SystemCertificate") or detail

def fetch_system_certs(session: requests.Session, base: str) -> Tuple[Optional[List[dict]], str]:
    """
    Paged fetch of up to all certificates:
      - Try page=1..N while we keep getting 200 and non-empty results
      - If only references arrive, dereference each to full objects
    """
    all_certs: List[dict] = []
    page = 1
    while True:
        refs, fulls, reason = _fetch_page(session, base, page)
        if refs is None and fulls is None:
            # A hard error or unexpected payload
            return None, reason
        if refs:
            # Deref each id
            got_any = False
            for res in refs:
                cid = res.get("id") or res.get("ID") or res.get("Id")
                if not cid:
                    href = (res.get("link") or {}).get("href") or ""
                    if href and "/" in href:
                        cid = href.split("/")[-1]
                if not cid:
                    continue
                ent = _fetch_cert_by_id(session, base, cid)
                if ent:
                    all_certs.append(ent)
                    got_any = True
            if not got_any and page == 1:
                # First page gave references but none could be dereferenced -> bail
                break
        elif fulls is not None:
            if not fulls:
                # empty list => end
                break
            all_certs.extend(fulls)
        else:
            # Neither refs nor fulls -> end
            break

        # Heuristic: if we got fewer than PAGE_SIZE references/full entries for this page,
        # assume it's the last page.
        count_this_page = len(refs) if refs else len(fulls or [])
        if count_this_page < PAGE_SIZE:
            break

        page += 1

    if not all_certs:
        return [], "OK (no certificates returned)"
    return all_certs, "OK"

# ---------- robust service-label matching ----------

_PUNCT_RE = re.compile(r"[\s_\-:/,;]+")

def _normalize_token(s: str) -> str:
    return _PUNCT_RE.sub("", s.strip().upper()) if s else ""

def _extract_usage_tokens(cert: dict, debug: bool=False, host: str="", name_hint: str="") -> List[str]:
    candidates: List[str] = []

    # Common fields (string or list)
    for key in ("usage", "usages", "services", "service", "usedFor", "keyUsage", "keyUsages", "bindedToServices"):
        v = cert.get(key)
        if isinstance(v, list):
            candidates.extend([str(x) for x in v])
        elif isinstance(v, str):
            parts = re.split(r"[;,]", v)
            candidates.extend([p for p in parts if p.strip()])

    # Nested structures: {"services":[{"name":"EAP Authentication"}]}
    for key in ("usage", "services"):
        v = cert.get(key)
        if isinstance(v, dict):
            name = v.get("name")
            if isinstance(name, str):
                candidates.append(name)
        elif isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    name = it.get("name")
                    if isinstance(name, str):
                        candidates.append(name)

    # Boolean hints
    if cert.get("isEap") is True:
        candidates.append("EAP Authentication")
    if cert.get("isAdmin") is True or cert.get("isAdminCert") is True:
        candidates.append("Admin")

    tokens = list({ _normalize_token(c) for c in candidates if isinstance(c, str) })

    if debug:
        raw_usage    = cert.get("usage")
        raw_services = cert.get("services")
        raw_binded   = cert.get("bindedToServices")
        log_event(
            f"DEBUG {host} cert='{name_hint}': usage={raw_usage} services={raw_services} bindedToServices={raw_binded} tokens={tokens}"
        )

    return tokens

def pick_cert_for_usage(certs: List[dict], usage_target: str, debug: bool=False, host: str="") -> Optional[dict]:
    target_norm = _normalize_token(usage_target)

    aliases = {target_norm}
    if target_norm == _normalize_token(USAGE_EAP):
        aliases.update({
            _normalize_token("EAP Authentication"),
            _normalize_token("EAP-Authentication"),
            _normalize_token("EAP"),
        })
    if target_norm == _normalize_token(USAGE_ADMIN):
        aliases.update({
            _normalize_token("Admin"),
            _normalize_token("Administration"),
        })

    for c in certs:
        name_hint = c.get("friendlyName") or c.get("name") or c.get("alias") or "(no friendlyName)"
        tokens = _extract_usage_tokens(c, debug=debug, host=host, name_hint=name_hint)
        if any(t in aliases for t in tokens):
            return c
    return None

# ---------- presentation helpers ----------

def cert_display_fields(c: dict) -> Tuple[str, str, str, Optional[int]]:
    name = c.get("friendlyName") or c.get("name") or c.get("alias") or "(no friendlyName)"
    issued_to = c.get("issuedTo") or c.get("commonName") or c.get("subjectCN") or ""
    exp_raw = c.get("expirationDate") or c.get("validTo") or c.get("notAfter")
    exp_dt = parse_iso_datetime(exp_raw) if isinstance(exp_raw, str) else None
    days_left = days_remaining(exp_dt)
    exp_iso = exp_dt.isoformat() + "Z" if exp_dt else (str(exp_raw) if exp_raw else "")
    return name, issued_to, exp_iso, days_left

def write_summary(results: List[Tuple[str, Dict[str, Dict[str, str]]]]) -> None:
    lines: List[str] = []
    lines.append(f"ISE Certificate Expiration Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Hosts File : {HOSTS_FILE}")
    lines.append("")

    for host, data in results:
        lines.append(f"Host: {host}")
        if "ERROR" in data:
            lines.append(f"  ERROR : {data['ERROR']}")
            lines.append("")
            continue
        for label in ("ADMIN", "EAP"):
            item = data.get(label)
            if not item:
                lines.append(f"  {label:5}: (no certificate bound)")
                continue
            lines.append(
                f"  {label:5}: name='{item['name']}', issuedTo='{item['issued_to']}', "
                f"expires='{item['expiration']}', days_left={item['days_left']}"
            )
        lines.append("")

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")

# ---------- main ----------

def main() -> int:
    parser = argparse.ArgumentParser(description="Cisco ISE cert expiration check (Admin & EAP)")
    parser.add_argument("--debug", action="store_true", help="Log raw usage fields and normalized tokens")
    args = parser.parse_args()

    print("ISE certificate check script started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    if not api_user:
        print("ERROR: API username is required.")
        return 2
    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2
    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    log_event("-" * 76)
    log_event("Starting certificate expiration check (Admin & EAP)")
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("-" * 76)

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    aggregated: List[Tuple[str, Dict[str, Dict[str, str]]]] = []

    for host in ise_hosts:
        base = f"https://{host}:{PORT}"
        result_row: Dict[str, Dict[str, str]] = {}
        try:
            certs, reason = fetch_system_certs(session, base)
            if certs is None:
                log_event(f"FAILED: {host} - {reason}")
                result_row["ERROR"] = reason
                aggregated.append((host, result_row))
                continue

            admin = pick_cert_for_usage(certs, USAGE_ADMIN, debug=args.debug, host=host)
            eap   = pick_cert_for_usage(certs, USAGE_EAP,   debug=args.debug, host=host)

            if admin:
                a_name, a_to, a_exp, a_days = cert_display_fields(admin)
                result_row["ADMIN"] = {
                    "name": a_name,
                    "issued_to": a_to,
                    "expiration": a_exp,
                    "days_left": str(a_days) if a_days is not None else "",
                }
                log_event(f"INFO: {host} - ADMIN cert '{a_name}' expires {a_exp} (days_left={a_days})")
            else:
                log_event(f"INFO: {host} - No ADMIN-bound certificate found")

            if eap:
                e_name, e_to, e_exp, e_days = cert_display_fields(eap)
                result_row["EAP"] = {
                    "name": e_name,
                    "issued_to": e_to,
                    "expiration": e_exp,
                    "days_left": str(e_days) if e_days is not None else "",
                }
                log_event(f"INFO: {host} - EAP cert '{e_name}' expires {e_exp} (days_left={e_days})")
            else:
                log_event(f"INFO: {host} - No EAP-bound certificate found")

            aggregated.append((host, result_row))

        except requests.exceptions.ConnectTimeout:
            reason = f"Connection timed out (port {PORT})"
            log_event(f"FAILED: {host} - {reason}")
            result_row["ERROR"] = reason
            aggregated.append((host, result_row))
        except requests.exceptions.ConnectionError:
            reason = f"Connection error (check network/ACL/DNS/port {PORT})"
            log_event(f"FAILED: {host} - {reason}")
            result_row["ERROR"] = reason
            aggregated.append((host, result_row))
        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            log_event(f"FAILED: {host} - {reason}")
            result_row["ERROR"] = reason
            aggregated.append((host, result_row))

    write_summary(aggregated)

    total = len(aggregated)
    errs  = sum(1 for _, d in aggregated if "ERROR" in d)
    log_event("-" * 76)
    log_event(f"Finished. Hosts processed: {total}   Errors: {errs}")
    log_event(f"Detailed log : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("-" * 76)
    return 0 if errs == 0 else 1

if __name__ == "__main__":
    sys.exit(main())