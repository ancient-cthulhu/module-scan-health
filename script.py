#!/usr/bin/env python3
"""
Veracode Bulk Scan Health Report
================================
Iterates over all application profiles and inspects the latest SAST build's
prescan results. Outputs one row per module with the raw platform-reported
issues so you can identify poorly packaged applications at scale.

Requirements:
  pip install veracode-api-signing requests

Authentication:
  Standard Veracode credentials file (~/.veracode/credentials)
  or env vars VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET.
"""

import argparse
import csv
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Optional

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


REGION_URLS: dict[str, dict[str, str]] = {
    "commercial": {
        "rest_base": "https://api.veracode.com",
        "xml_base": "https://analysiscenter.veracode.com",
    },
    "european": {
        "rest_base": "https://api.veracode.eu",
        "xml_base": "https://analysiscenter.veracode.eu",
    },
}

XML_NS: dict[str, str] = {
    "buildlist": "https://analysiscenter.veracode.com/schema/2.0/buildlist",
    "buildinfo": "https://analysiscenter.veracode.com/schema/4.0/buildinfo",
    "prescan": "https://analysiscenter.veracode.com/schema/2.0/prescanresults",
    "sandboxlist": "https://analysiscenter.veracode.com/schema/2.0/sandboxlist",
    "dr": "https://www.veracode.com/schema/reports/export/1.0",
}

_OK_STATUSES: set[str] = {"OK", "Published", ""}
_NOOP_LOCK: threading.Lock = threading.Lock()
_REQUEST_TIMEOUT: int = 60

CSV_COLUMNS: list[str] = [
    "Application",
    "App ID",
    "Business Unit",
    "Scan Context",
    "Build ID",
    "Scan Name",
    "Scan State",
    "Scan Date",
    "Days Since Scan",
    "Module",
    "Module ID",
    "App File ID",
    "Checksum",
    "Platform",
    "Size",
    "Status",
    "Is Dependency",
    "Fatal Errors",
    "Verdict",
    "Issues",
    "Error",
    "Issue Severity",
    "Issue Categories",
    "Packaging Recommendation",
]


FATAL_STATUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\(fatal\)", re.IGNORECASE), "Fatal prescan error"),
    (re.compile(r"pdb files not loadable", re.IGNORECASE), "PDB not loadable"),
    (re.compile(r"pdb files missing", re.IGNORECASE), "Missing PDB"),
    (re.compile(r"unsupported architecture", re.IGNORECASE), "Unsupported architecture"),
    (re.compile(r"unsupported platform", re.IGNORECASE), "Unsupported platform"),
    (re.compile(r"unsupported compiler", re.IGNORECASE), "Unsupported compiler"),
    (re.compile(r"corrupt header", re.IGNORECASE), "Corrupt header"),
]

FATAL_SUPPORT_ISSUE_RE: re.Pattern = re.compile(
    r"support\s+issue.*fatal|fatal.*support\s+issue", re.IGNORECASE
)

WARNING_STATUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"jsp compilation error", re.IGNORECASE), "JSP compilation errors"),
    (re.compile(r"missing debug symbols", re.IGNORECASE), "Missing debug symbols"),
    (re.compile(r"missing debug info", re.IGNORECASE), "Missing debug symbols"),
    (re.compile(r"incremental linking", re.IGNORECASE), "Incremental linking"),
    (re.compile(r"parse failure", re.IGNORECASE), "Parse failures"),
    (re.compile(r"minified", re.IGNORECASE), "Minified/obfuscated JS/TS"),
    (re.compile(r"obfuscated", re.IGNORECASE), "Minified/obfuscated JS/TS"),
    (re.compile(r"unsupported framework", re.IGNORECASE), "Unsupported framework"),
    (re.compile(r"missing.*precompiled.*asp", re.IGNORECASE), "Missing ASP.NET precompilation"),
    (re.compile(r"precompiled.*asp.*missing", re.IGNORECASE), "Missing ASP.NET precompilation"),
]

WARNING_ISSUE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"no supporting files or pdb", re.IGNORECASE), "No supporting files or PDB"),
    (re.compile(r"php files could not be compiled", re.IGNORECASE), "PHP compilation failure"),
    (re.compile(r"not currently supported by veracode", re.IGNORECASE), "Unsupported compiler"),
    (re.compile(r"pdb.*mismatch|mismatch.*pdb|debug info.*doesn.t match|doesn.t match.*debug info", re.IGNORECASE), "PDB mismatch"),
    (re.compile(r"precompil.*asp\.net|asp\.net.*precompil", re.IGNORECASE), "Missing ASP.NET precompilation"),
]

WARNING_FILE_ISSUE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"compiled without debug symbols", re.IGNORECASE), "Missing debug symbols"),
    (re.compile(r"compiled using obfuscation", re.IGNORECASE), "Obfuscation detected"),
    (re.compile(r"corrupt header", re.IGNORECASE), "Corrupt header"),
]

FATAL_FILE_ISSUE_RE: re.Pattern = re.compile(r"\(required\)", re.IGNORECASE)

BENIGN_FILE_ISSUE_RE: re.Pattern = re.compile(r"^found \(optional\)$", re.IGNORECASE)

CATEGORY_RECOMMENDATIONS: dict[str, str] = {
    "Missing PDB": "Include PDB files from the same Debug build",
    "PDB not loadable": "Ensure PDB files are valid and match the binary version",
    "PDB mismatch": "Perform a clean rebuild - PDB files don't match the binary",
    "Missing debug symbols": "Recompile with debug symbols (Debug configuration)",
    "Corrupt header": "Recompile the module - headers may have been modified post-compilation",
    "JSP compilation errors": "Ensure all JSP dependencies and classes are included in the WAR",
    "Unsupported architecture": "Recompile for a supported platform (see Veracode supported platforms list)",
    "Unsupported platform": "Recompile for a supported platform (see Veracode supported platforms list)",
    "Unsupported compiler": "Recompile for a supported platform (see Veracode supported platforms list)",
    "Unsupported framework": "Findings may be incomplete - review if the framework is in Veracode's supported list",
    "Parse failures": "Review source files for syntax errors and include required dependencies",
    "Minified/obfuscated JS/TS": "Upload original non-minified, non-obfuscated source files",
    "Incremental linking": "Recompile without incremental linking enabled",
    "PHP compilation failure": "Verify all PHP files compile correctly before uploading",
    "Obfuscation detected": "Do not obfuscate binaries before uploading (Dotfuscator Community Edition is OK for .NET)",
    "Missing ASP.NET precompilation": "Precompile ASP.NET pages before upload (use Veracode Static for VS or aspnet_compiler)",
    "Fatal prescan error": "Review the prescan error details and repackage the upload",
    "Fatal support issue": "Contact Veracode support - the module encountered a fatal analysis error",
    "No supporting files or PDB": "Include PDB files from the same Debug build (.NET) or supporting JARs (Java)",
    "Required file missing": "Include all required files indicated by the prescan results",
    "Support issue (non-fatal)": "Review the support issue details - scan proceeded but may have reduced coverage",
}

_DOTNET_PLATFORM_RE: re.Pattern = re.compile(
    r"\.net|clr|csharp|c#|vb\.net|msil|dotnet", re.IGNORECASE
)


def classify_module(
    module: dict[str, Any],
    debug_log: Optional[callable] = None,
) -> tuple[str, list[str], list[str]]:
    """
    Classify a single module's prescan findings into a severity tier.

    Returns:
        (severity, categories, recommendations)
        severity: "FATAL", "WARNING", "INFO", or "CLEAN"
        categories: list of matched category labels
        recommendations: list of actionable recommendation strings
    """
    categories: list[str] = []
    seen_categories: set[str] = set()

    def add_category(cat: str, source: str = "") -> None:
        if cat not in seen_categories:
            seen_categories.add(cat)
            categories.append(cat)
            if debug_log:
                debug_log(f"    Classifier: [{cat}] matched on: {source!r}")

    status_text = module.get("status", "")
    has_fatal = module.get("has_fatal_errors", False)
    is_dep = module.get("is_dependency", False)
    platform = module.get("platform", "")
    issues = module.get("issues", [])
    file_issues = module.get("file_issues_raw", [])

    if has_fatal:
        add_category("Fatal prescan error", "has_fatal_errors=true")

    if status_text:
        if FATAL_SUPPORT_ISSUE_RE.search(status_text):
            add_category("Fatal support issue", f"status={status_text}")
        for pat, cat in FATAL_STATUS_PATTERNS:
            if pat.search(status_text):
                add_category(cat, f"status={status_text}")

    for fi in file_issues:
        details = fi.get("details", "")
        if FATAL_FILE_ISSUE_RE.search(details):
            add_category("Required file missing", f"file_issue={details}")

    fatal_cats = {
        "Fatal prescan error", "Fatal support issue", "PDB not loadable",
        "Missing PDB", "Unsupported architecture", "Unsupported platform",
        "Unsupported compiler", "Corrupt header", "Required file missing",
    }
    has_fatal_category = bool(seen_categories & fatal_cats)

    if status_text:
        for pat, cat in WARNING_STATUS_PATTERNS:
            if pat.search(status_text):
                add_category(cat, f"status={status_text}")

    for issue_text in issues:
        for pat, cat in WARNING_ISSUE_PATTERNS:
            if pat.search(issue_text):
                if cat == "No supporting files or PDB" and is_dep:
                    if not _DOTNET_PLATFORM_RE.search(platform):
                        add_category(cat + " (dependency, non-.NET)", f"issue={issue_text}")
                        continue
                add_category(cat, f"issue={issue_text}")

    for fi in file_issues:
        details = fi.get("details", "")
        if BENIGN_FILE_ISSUE_RE.match(details):
            continue
        matched = False
        for pat, cat in WARNING_FILE_ISSUE_PATTERNS:
            if pat.search(details):
                if cat == "Corrupt header" and has_fatal:
                    continue
                add_category(cat, f"file_issue={details}")
                matched = True
        if not matched and not FATAL_FILE_ISSUE_RE.search(details):
            add_category("Other file issue", f"file_issue={details}")

    if status_text and not has_fatal_category:
        if re.search(r"support\s+issue", status_text, re.IGNORECASE):
            if not FATAL_SUPPORT_ISSUE_RE.search(status_text):
                add_category("Support issue (non-fatal)", f"status={status_text}")

    if has_fatal_category:
        severity = "FATAL"
    elif seen_categories - {
        "No supporting files or PDB (dependency, non-.NET)",
        "Support issue (non-fatal)",
        "Other file issue",
    }:
        severity = "WARNING"
    elif seen_categories:
        severity = "INFO"
    else:
        severity = "CLEAN"

    recommendations: list[str] = []
    seen_recs: set[str] = set()
    for cat in categories:
        lookup = cat.replace(" (dependency, non-.NET)", "")
        rec = CATEGORY_RECOMMENDATIONS.get(lookup, "")
        if rec and rec not in seen_recs:
            seen_recs.add(rec)
            recommendations.append(rec)

    return severity, categories, recommendations


def severity_to_verdict(severity: str) -> str:
    """Map classifier severity to backwards-compatible Verdict column value."""
    if severity == "FATAL":
        return "FAIL"
    if severity == "WARNING":
        return "WARNING"
    return "PASS"


class RateLimiter:
    """
    Token bucket rate limiter. Shared across all worker threads.
    Sleeps outside the lock so waiting threads don't block others.
    Uses time.monotonic() to be immune to clock adjustments.
    """

    def __init__(self, rate: float) -> None:
        if rate <= 0:
            raise ValueError("Rate must be greater than 0")
        self._rate: float = rate
        self._tokens: float = 1.0
        self._max_tokens: float = rate
        self._last_refill: float = time.monotonic()
        self._lock: threading.Lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                wait = (1.0 - self._tokens) / self._rate

            time.sleep(wait)


class VeracodeClient:
    """
    Wraps Veracode REST and XML APIs with HMAC auth.
    Each worker thread should create its own instance (owns a requests.Session).
    """

    def __init__(
        self,
        region: str,
        ca_cert: Optional[str],
        verbose: bool,
        debug: bool,
        rate_limiter: RateLimiter,
        print_lock: Optional[threading.Lock] = None,
    ) -> None:
        self.region: str = region
        self.urls: dict[str, str] = REGION_URLS[region]
        self.verbose: bool = verbose
        self.debug: bool = debug
        self._rate_limiter: RateLimiter = rate_limiter
        self._print_lock: threading.Lock = print_lock or _NOOP_LOCK

        self.session: requests.Session = requests.Session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()
        self.session.headers.update({"User-Agent": "BulkScanHealth/3.0"})
        if ca_cert:
            self.session.verify = ca_cert

    def close(self) -> None:
        self.session.close()

    def log(self, message: str) -> None:
        if self.verbose:
            with self._print_lock:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] {message}")

    def debug_log(self, message: str) -> None:
        if self.debug:
            with self._print_lock:
                print(f"  [DEBUG {datetime.now().strftime('%H:%M:%S')}] {message}")

    def _rate_limited_get(self, url: str, params: Optional[dict] = None) -> requests.Response:
        """
        GET with rate limiting and retry on 429/5xx.
        Retry-After header. Exponential backoff: 2s, 4s, 8s, 16s, 32s.
        """
        max_retries = 5
        response: Optional[requests.Response] = None

        for attempt in range(max_retries + 1):
            self._rate_limiter.acquire()
            response = self.session.get(url, params=params, timeout=_REQUEST_TIMEOUT)

            if response.status_code == 429:
                if attempt >= max_retries:
                    response.raise_for_status()
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = int(retry_after)
                    except ValueError:
                        wait = 2 ** (attempt + 1)
                else:
                    wait = 2 ** (attempt + 1)
                self.log(f"  429 rate limited, waiting {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
                continue

            if response.status_code >= 500:
                if attempt >= max_retries:
                    response.raise_for_status()
                wait = 2 ** (attempt + 1)
                self.log(f"  HTTP {response.status_code}, retrying in {wait}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
                continue

            response.raise_for_status()
            return response

        response.raise_for_status()
        return response

    def get_all_applications(
        self, name_filter: Optional[str] = None, max_apps: Optional[int] = None
    ) -> list[dict[str, Any]]:
        apps: list[dict[str, Any]] = []
        page = 0
        page_size = 100
        url = f"{self.urls['rest_base']}/appsec/v1/applications"

        while True:
            params: dict[str, Any] = {"page": page, "size": page_size}
            if name_filter:
                params["name"] = name_filter
            response = self._rate_limited_get(url, params=params)
            data = response.json()
            app_list = data.get("_embedded", {}).get("applications", [])
            if not app_list:
                break
            for app in app_list:
                profile = app.get("profile", {})
                apps.append({
                    "app_id": app.get("id"),
                    "app_name": profile.get("name", "Unknown"),
                    "business_unit": profile.get("business_unit", {}).get("name", "N/A"),
                    "last_completed_scan_date": app.get("last_completed_scan_date", ""),
                })
                if max_apps and len(apps) >= max_apps:
                    return apps
            total_pages = data.get("page", {}).get("total_pages", 1)
            page += 1
            if page >= total_pages:
                break
        return apps

    def _xml_get(self, endpoint: str, params: dict) -> str:
        url = f"{self.urls['xml_base']}{endpoint}"
        response = self._rate_limited_get(url, params=params)
        return response.text

    def get_build_list(
        self, app_id: int, sandbox_id: Optional[str] = None
    ) -> list[dict[str, str]]:
        params: dict[str, Any] = {"app_id": app_id}
        if sandbox_id is not None:
            params["sandbox_id"] = sandbox_id
        root = ET.fromstring(self._xml_get("/api/5.0/getbuildlist.do", params))
        return [
            {"build_id": el.get("build_id"), "version": el.get("version", "")}
            for el in root.findall("buildlist:build", XML_NS)
        ]

    def get_build_info(
        self, app_id: int, build_id: str, sandbox_id: Optional[str] = None
    ) -> Optional[dict[str, str]]:
        params: dict[str, Any] = {"app_id": app_id, "build_id": build_id}
        if sandbox_id is not None:
            params["sandbox_id"] = sandbox_id
        root = ET.fromstring(self._xml_get("/api/5.0/getbuildinfo.do", params))
        build_el = root.find("buildinfo:build", XML_NS)
        if build_el is None:
            return None
        info: dict[str, str] = {
            "build_id": build_el.get("build_id", ""),
            "version": build_el.get("version", ""),
            "policy_updated_date": build_el.get("policy_updated_date", ""),
        }
        au = build_el.find("buildinfo:analysis_unit", XML_NS)
        if au is not None:
            info["status"] = au.get("status", "")
            info["published_date"] = au.get("published_date", "")
        return info

    def get_prescan_results(
        self, app_id: int, build_id: Optional[str] = None, sandbox_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"app_id": app_id}
        if build_id is not None:
            params["build_id"] = build_id
        if sandbox_id is not None:
            params["sandbox_id"] = sandbox_id
        xml_text = self._xml_get("/api/5.0/getprescanresults.do", params)

        if self.debug:
            preview = xml_text[:2000].replace("\n", " ")
            self.log(f"  Raw prescan XML: {preview}")

        root = ET.fromstring(xml_text)

        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        modules: list[dict[str, Any]] = []
        for el in root.iter(f"{ns}module"):
            issues = [
                i.get("details", "")
                for i in el.iter(f"{ns}issue")
                if i.tag == f"{ns}issue"
            ]
            file_issues_raw: list[dict[str, str]] = []
            file_issues_display: list[str] = []
            for fi in el.iter(f"{ns}file_issue"):
                details = fi.get("details", "")
                file_issues_raw.append({"details": details})
                if details.lower() != "found (optional)":
                    file_issues_display.append(details)

            modules.append({
                "name": el.get("name", ""),
                "module_id": el.get("id", ""),
                "app_file_id": el.get("app_file_id", ""),
                "checksum": el.get("checksum", ""),
                "platform": el.get("platform", ""),
                "size": el.get("size", ""),
                "status": el.get("status", ""),
                "has_fatal_errors": el.get("has_fatal_errors", "false") == "true",
                "is_dependency": el.get("is_dependency", "false") == "true",
                "issues": issues + file_issues_display,
                "file_issues_raw": file_issues_raw,
            })

            if self.debug and not (issues or file_issues_display):
                child_tags = [c.tag for c in el]
                self.log(f"  Module '{el.get('name')}' children: {child_tags}")

        return modules

    def get_detailed_report_modules(self, build_id: str) -> dict[str, Any]:
        """
        Fallback: get module info + scan dates from the detailed report.
        Returns {"modules": [...], "submitted_date": "...", "published_date": "..."}.
        """
        xml_text = self._xml_get("/api/5.0/detailedreport.do", {"build_id": build_id})
        root = ET.fromstring(xml_text)
        result: dict[str, Any] = {"modules": [], "submitted_date": "", "published_date": ""}

        static = root.find("dr:static-analysis", XML_NS)
        if static is None:
            return result

        result["submitted_date"] = static.get("submitted_date", "")
        result["published_date"] = static.get("published_date", "")

        modules_el = static.find("dr:modules", XML_NS)
        if modules_el is None:
            return result
        for el in modules_el.findall("dr:module", XML_NS):
            compiler = el.get("compiler", "")
            os_name = el.get("os", "")
            arch = el.get("architecture", "")
            platform = f"{arch} / {os_name} / {compiler}" if compiler else ""
            result["modules"].append({
                "name": el.get("name", ""),
                "module_id": "",
                "app_file_id": "",
                "checksum": "",
                "platform": platform,
                "size": "",
                "status": "Published",
                "has_fatal_errors": False,
                "is_dependency": False,
                "issues": [],
                "file_issues_raw": [],
            })
        return result

    def get_sandbox_list(self, app_id: int) -> list[dict[str, str]]:
        root = ET.fromstring(self._xml_get("/api/5.0/getsandboxlist.do", {"app_id": app_id}))
        return [
            {"sandbox_id": el.get("sandbox_id"), "sandbox_name": el.get("sandbox_name", "")}
            for el in root.findall("sandboxlist:sandbox", XML_NS)
        ]


def process_app(
    client: VeracodeClient,
    app: dict[str, Any],
    stale_days: int,
    include_sandboxes: bool,
) -> list[dict[str, Any]]:
    """Process a single application. Returns list of row dicts."""
    app_id = app["app_id"]
    app_name = app["app_name"]
    rows: list[dict[str, Any]] = []

    contexts: list[dict[str, Any]] = [{"sandbox_id": None, "context": "Policy"}]
    if include_sandboxes:
        try:
            for sb in client.get_sandbox_list(app_id):
                contexts.append({
                    "sandbox_id": sb["sandbox_id"],
                    "context": f"Sandbox: {sb['sandbox_name']}",
                })
        except Exception as e:
            client.log(f"  Could not list sandboxes for {app_name}: {type(e).__name__}: {e}")

    for ctx in contexts:
        sandbox_id = ctx["sandbox_id"]
        context_label = ctx["context"]

        try:
            builds = client.get_build_list(app_id, sandbox_id=sandbox_id)
        except Exception as e:
            rows.append(_error_row(app, context_label, f"Could not retrieve builds: {e}"))
            continue

        if not builds:
            rows.append(_error_row(app, context_label, "No builds found"))
            continue

        build_id = builds[0]["build_id"]
        scan_name = builds[0]["version"]

        scan_status = ""
        scan_date = ""
        days_since = ""

        published_date = ""
        rest_date = app.get("last_completed_scan_date", "") if sandbox_id is None else ""
        policy_date = ""

        try:
            info = client.get_build_info(app_id, build_id, sandbox_id=sandbox_id)
            if info:
                scan_status = info.get("status", "")
                published_date = info.get("published_date", "")
                policy_date = info.get("policy_updated_date", "")
        except Exception as e:
            client.log(f"  get_build_info failed for {app_name}: {type(e).__name__}: {e}")

        raw_date = published_date or rest_date or policy_date
        if raw_date:
            scan_date = raw_date[:10] if len(raw_date) >= 10 else raw_date
            try:
                dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                days_since = (datetime.now(timezone.utc) - dt).days
            except (ValueError, TypeError):
                pass

        modules: list[dict[str, Any]] = []
        source = ""

        try:
            modules = client.get_prescan_results(app_id, sandbox_id=sandbox_id)
            if modules:
                source = "prescan"
                client.log(f"  Got {len(modules)} module(s) from prescan (no build_id)")
        except Exception as e:
            client.log(f"  Prescan (no build_id) failed: {type(e).__name__}: {e}")

        if not modules and build_id:
            try:
                modules = client.get_prescan_results(app_id, build_id=build_id, sandbox_id=sandbox_id)
                if modules:
                    source = "prescan"
                    client.log(f"  Got {len(modules)} module(s) from prescan (build_id={build_id})")
            except Exception as e:
                client.log(f"  Prescan (build_id={build_id}) failed: {type(e).__name__}: {e}")

        if not modules and build_id:
            try:
                dr_result = client.get_detailed_report_modules(build_id)
                modules = dr_result["modules"]
                if modules:
                    source = "detailedreport"
                    client.log(f"  Got {len(modules)} module(s) from detailed report")
                if not scan_date:
                    dr_date = dr_result.get("published_date", "") or dr_result.get("submitted_date", "")
                    if dr_date:
                        scan_date = dr_date[:10] if len(dr_date) >= 10 else dr_date
                        try:
                            dt = datetime.fromisoformat(dr_date.replace("Z", "+00:00").replace(" UTC", "+00:00"))
                            days_since = (datetime.now(timezone.utc) - dt).days
                        except (ValueError, TypeError):
                            pass
            except Exception as e:
                client.log(f"  Detailed report failed: {type(e).__name__}: {e}")

        if not scan_date and build_id and source == "prescan":
            try:
                dr_result = client.get_detailed_report_modules(build_id)
                dr_date = dr_result.get("published_date", "") or dr_result.get("submitted_date", "")
                if dr_date:
                    scan_date = dr_date[:10] if len(dr_date) >= 10 else dr_date
                    try:
                        dt = datetime.fromisoformat(dr_date.replace("Z", "+00:00").replace(" UTC", "+00:00"))
                        days_since = (datetime.now(timezone.utc) - dt).days
                    except (ValueError, TypeError):
                        pass
                    client.log(f"  Got scan date from detailed report: {scan_date}")
            except Exception:
                pass

        scan_state = scan_status or "Unknown"

        if not scan_date and scan_state:
            state_lower = scan_state.lower()
            if "incomplete" in state_lower:
                scan_date = "Not started"
            elif "prescan submitted" in state_lower:
                scan_date = "Prescan in progress"
            elif "prescan success" in state_lower or "no modules defined" in state_lower:
                scan_date = "Awaiting module selection"
            elif "prescan failed" in state_lower:
                scan_date = "Prescan failed"
            elif "scan in process" in state_lower:
                scan_date = "Scan in progress"
            elif "vendor" in state_lower:
                scan_date = "Awaiting vendor"
            elif scan_state == "Unknown":
                scan_date = "No date available"

        if not modules:
            rows.append(_error_row(
                app, context_label, "No modules found",
                build_id=build_id, scan_name=scan_name,
                scan_state=scan_state, scan_date=scan_date, days_since=days_since,
            ))
            continue

        debug_fn = client.debug_log if client.debug else None

        for module in modules:
            all_issues = module["issues"]
            status_text = module.get("status", "")

            severity, categories, recommendations = classify_module(module, debug_log=debug_fn)
            verdict = severity_to_verdict(severity)
            issue_text = "; ".join(all_issues) if all_issues else ""

            note = ""
            if not all_issues and status_text in _OK_STATUSES and source == "prescan":
                note = "Prescan issue details not available for this scan"
            elif source == "detailedreport":
                note = "Module data from published report (no prescan details)"

            rows.append({
                "Application": app_name,
                "App ID": app_id,
                "Business Unit": app["business_unit"],
                "Scan Context": context_label,
                "Build ID": build_id,
                "Scan Name": scan_name,
                "Scan State": scan_state,
                "Scan Date": scan_date,
                "Days Since Scan": days_since,
                "Module": module["name"],
                "Module ID": module.get("module_id", ""),
                "App File ID": module.get("app_file_id", ""),
                "Checksum": module.get("checksum", ""),
                "Platform": module["platform"],
                "Size": module["size"],
                "Status": status_text,
                "Is Dependency": module["is_dependency"],
                "Fatal Errors": module["has_fatal_errors"],
                "Verdict": verdict,
                "Issues": issue_text,
                "Error": note,
                "Issue Severity": severity,
                "Issue Categories": "; ".join(categories) if categories else "",
                "Packaging Recommendation": "; ".join(recommendations) if recommendations else "",
            })

    return rows


def _error_row(
    app: dict[str, Any],
    context_label: str,
    error_msg: str,
    build_id: str = "",
    scan_name: str = "",
    scan_state: str = "",
    scan_date: str = "",
    days_since: Any = "",
) -> dict[str, Any]:
    return {
        "Application": app["app_name"],
        "App ID": app["app_id"],
        "Business Unit": app["business_unit"],
        "Scan Context": context_label,
        "Build ID": build_id,
        "Scan Name": scan_name,
        "Scan State": scan_state,
        "Scan Date": scan_date,
        "Days Since Scan": days_since,
        "Module": "",
        "Platform": "",
        "Size": "",
        "Status": "",
        "Is Dependency": "",
        "Fatal Errors": "",
        "Verdict": "ERROR",
        "Issues": "",
        "Error": error_msg,
        "Issue Severity": "",
        "Issue Categories": "",
        "Packaging Recommendation": "",
    }


def compute_app_health(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """
    Compute a packaging health verdict per (app_name, scan_context) pair.

    Returns dict keyed by "app_name||scan_context" with:
      app_name, app_id, business_unit, scan_context, health_verdict,
      modules: [{name, severity, categories, recommendations}, ...]
    """
    groups: dict[str, dict[str, Any]] = {}

    for r in rows:
        if r["Verdict"] == "ERROR" and not r["Module"]:
            continue

        key = f"{r['Application']}||{r['Scan Context']}"
        if key not in groups:
            groups[key] = {
                "app_name": r["Application"],
                "app_id": r["App ID"],
                "business_unit": r["Business Unit"],
                "scan_context": r["Scan Context"],
                "build_id": r["Build ID"],
                "scan_date": r["Scan Date"],
                "modules": [],
            }

        groups[key]["modules"].append({
            "name": r["Module"],
            "is_dependency": r["Is Dependency"],
            "severity": r["Issue Severity"],
            "categories": r["Issue Categories"],
            "recommendations": r["Packaging Recommendation"],
        })

    for key, group in groups.items():
        has_fatal_toplevel = any(
            m["severity"] == "FATAL" and not m["is_dependency"]
            for m in group["modules"]
        )
        has_warning = any(
            m["severity"] == "WARNING"
            for m in group["modules"]
        )

        if has_fatal_toplevel:
            group["health_verdict"] = "BROKEN"
        elif has_warning:
            group["health_verdict"] = "DEGRADED"
        else:
            group["health_verdict"] = "HEALTHY"

    return groups


def _worker(
    app: dict[str, Any],
    region: str,
    ca_cert: Optional[str],
    verbose: bool,
    debug: bool,
    rate_limiter: RateLimiter,
    stale_days: int,
    include_sandboxes: bool,
    counter: list[int],
    total: int,
    counter_lock: threading.Lock,
    print_lock: threading.Lock,
) -> list[dict[str, Any]]:
    """
    Worker function executed in each thread.
    Creates its own VeracodeClient (own requests.Session) and closes it in finally.
    """
    client = VeracodeClient(region, ca_cert, verbose, debug, rate_limiter, print_lock)
    try:
        with counter_lock:
            counter[0] += 1
            idx = counter[0]

        with print_lock:
            print(f"[{idx}/{total}] {app['app_name']} (ID: {app['app_id']})")

        return process_app(client, app, stale_days, include_sandboxes)
    except Exception as e:
        with print_lock:
            print(f"  ERROR processing {app['app_name']}: {e}")
        return [_error_row(app, "Policy", f"Unexpected error: {e}")]
    finally:
        client.close()


def write_csv(records: list[dict[str, Any]], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow(record)


def write_json(records: list[dict[str, Any]], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, default=str)


def write_health_json(app_health: dict[str, dict[str, Any]], output_path: str) -> None:
    health_list = []
    for key in sorted(app_health.keys()):
        group = app_health[key]
        health_list.append({
            "app_name": group["app_name"],
            "app_id": group["app_id"],
            "business_unit": group["business_unit"],
            "scan_context": group["scan_context"],
            "build_id": group["build_id"],
            "scan_date": group["scan_date"],
            "health_verdict": group["health_verdict"],
            "modules": group["modules"],
        })
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(health_list, f, indent=2, default=str)


def print_summary(records: list[dict[str, Any]]) -> None:
    if not records:
        print("No data.")
        return

    apps: set[str] = set()
    apps_with_issues: set[str] = set()
    module_count = 0
    verdict_counts: dict[str, int] = {"PASS": 0, "WARNING": 0, "FAIL": 0, "ERROR": 0}
    severity_counts: dict[str, int] = {"FATAL": 0, "WARNING": 0, "INFO": 0, "CLEAN": 0}
    fail_details: list[dict[str, Any]] = []
    warn_details: list[dict[str, Any]] = []

    for r in records:
        app_name = r["Application"]
        verdict = r["Verdict"]
        apps.add(app_name)

        if r["Module"]:
            module_count += 1
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
            sev = r.get("Issue Severity", "")
            if sev in severity_counts:
                severity_counts[sev] += 1
            if verdict == "FAIL":
                fail_details.append(r)
            elif verdict == "WARNING":
                warn_details.append(r)
        elif verdict == "ERROR":
            verdict_counts["ERROR"] += 1

        if verdict in {"FAIL", "WARNING"}:
            apps_with_issues.add(app_name)

    app_health = compute_app_health(records)
    health_counts: dict[str, int] = {"BROKEN": 0, "DEGRADED": 0, "HEALTHY": 0}
    for group in app_health.values():
        v = group["health_verdict"]
        health_counts[v] = health_counts.get(v, 0) + 1

    print()
    print("=" * 60)
    print("  BULK SCAN HEALTH SUMMARY")
    print("=" * 60)
    print(f"  Applications:          {len(apps)}")
    print(f"  Total modules:         {module_count}")
    print(f"  Modules PASS:          {verdict_counts['PASS']}")
    print(f"  Modules WARNING:       {verdict_counts['WARNING']}")
    print(f"  Modules FAIL:          {verdict_counts['FAIL']}")
    if verdict_counts["ERROR"]:
        print(f"  Errors:                {verdict_counts['ERROR']}")
    print(f"  Apps with issues:      {len(apps_with_issues)}")
    print("-" * 60)
    print(f"  Severity breakdown:")
    print(f"    FATAL:   {severity_counts['FATAL']}")
    print(f"    WARNING: {severity_counts['WARNING']}")
    print(f"    INFO:    {severity_counts['INFO']}")
    print(f"    CLEAN:   {severity_counts['CLEAN']}")
    print("-" * 60)
    print(f"  Packaging health:")
    print(f"    BROKEN:   {health_counts['BROKEN']} app(s)")
    print(f"    DEGRADED: {health_counts['DEGRADED']} app(s)")
    print(f"    HEALTHY:  {health_counts['HEALTHY']} app(s)")
    print("-" * 60)

    if fail_details:
        print()
        print("  FAIL modules (cannot scan):")
        for r in fail_details:
            cats = r.get("Issue Categories", "")
            rec = r.get("Packaging Recommendation", "")
            print(f"    {r['Application']} -> {r['Module']}")
            print(f"      Issues: {r['Issues']}")
            if cats:
                print(f"      Categories: {cats}")
            if rec:
                print(f"      Fix: {rec}")

    if warn_details:
        print()
        print("  WARNING modules (reduced scan quality):")
        for r in warn_details:
            cats = r.get("Issue Categories", "")
            rec = r.get("Packaging Recommendation", "")
            print(f"    {r['Application']} -> {r['Module']}")
            print(f"      Issues: {r['Issues']}")
            if cats:
                print(f"      Categories: {cats}")
            if rec:
                print(f"      Fix: {rec}")

    print()
    print("=" * 60)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Veracode Bulk Scan Health Report - one row per module."
    )
    parser.add_argument("--output-csv", default="scan_health_report.csv")
    parser.add_argument("--output-json", default=None)
    parser.add_argument("--output-health-json", default=None,
                        help="Write per-app packaging health verdicts to a JSON file")
    parser.add_argument("--region", choices=["commercial", "european"], default="commercial")
    parser.add_argument("--stale-days", type=int, default=90)
    parser.add_argument("--app-name-filter", default=None)
    parser.add_argument("--max-apps", type=int, default=None)
    parser.add_argument("--include-sandboxes", action="store_true")
    parser.add_argument("--ca-cert", default=None)
    parser.add_argument("--max-workers", type=int, default=5,
                        help="Concurrent threads for parallel processing (default: 5)")
    parser.add_argument("--rate-limit", type=float, default=4.0,
                        help="Max API requests per second across all threads (default: 4)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print progress per app")
    parser.add_argument("--debug", action="store_true",
                        help="Dump raw API responses (for troubleshooting)")

    args = parser.parse_args()

    if args.rate_limit <= 0:
        parser.error("--rate-limit must be greater than 0")
    if args.max_workers < 1:
        parser.error("--max-workers must be at least 1")
    if args.ca_cert and not os.path.isfile(args.ca_cert):
        parser.error(f"CA certificate file not found: {args.ca_cert}")

    return args


def main() -> None:
    args = parse_args()

    rate_limiter = RateLimiter(args.rate_limit)

    main_client = VeracodeClient(
        args.region, args.ca_cert, args.verbose, args.debug, rate_limiter
    )

    print("Fetching application list...")
    try:
        apps = main_client.get_all_applications(
            name_filter=args.app_name_filter, max_apps=args.max_apps
        )
    finally:
        main_client.close()

    total = len(apps)
    print(f"Found {total} application(s). Processing with {args.max_workers} workers "
          f"at {args.rate_limit} req/s.\n")

    if total == 0:
        print("Nothing to do.")
        return

    counter: list[int] = [0]
    counter_lock = threading.Lock()
    print_lock = threading.Lock()

    all_rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        futures = {
            executor.submit(
                _worker, app, args.region, args.ca_cert, args.verbose, args.debug,
                rate_limiter, args.stale_days, args.include_sandboxes,
                counter, total, counter_lock, print_lock
            ): app
            for app in apps
        }

        for future in as_completed(futures):
            app = futures[future]
            try:
                rows = future.result()
                all_rows.extend(rows)
            except Exception as e:
                with print_lock:
                    print(f"  FATAL: {app['app_name']} raised: {e}")
                all_rows.append(_error_row(app, "Policy", f"Thread error: {e}"))

    all_rows.sort(key=lambda r: (r["Application"], r["Scan Context"], r["Module"]))

    write_csv(all_rows, args.output_csv)
    print(f"\nCSV written to: {args.output_csv}")

    if args.output_json:
        write_json(all_rows, args.output_json)
        print(f"JSON written to: {args.output_json}")

    if args.output_health_json:
        app_health = compute_app_health(all_rows)
        write_health_json(app_health, args.output_health_json)
        print(f"Health JSON written to: {args.output_health_json}")

    print_summary(all_rows)


if __name__ == "__main__":
    main()
