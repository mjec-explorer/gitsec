import json
from pathlib import Path
from typing import Any, List, Optional

from ..models.finding import DependencyFinding, Finding, SecretFinding

DEFAULT_SEVERITY = "Unknown"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
DEPENDENCY_CATEGORY = "Dependency Vulnerability"
SECRET_CATEGORY = "Secrets"
SECRET_REMEDIATION = "Rotate this credential immediately. Remove it from repository history and replace it everywhere it was used."


class HtmlReportWriter:
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self._security_findings: List[Finding] = []
        self._dependency_findings: List[DependencyFinding] = []
        self._deprecated_dependencies: List[dict] = []
        self._unpinned_dependencies: List[dict] = []
        self._secret_findings: List[SecretFinding] = []

    def add_security_findings(self, findings: List[Finding]) -> None:
        self._security_findings = [finding for finding in findings if not finding.is_error]

    def add_dependency_findings(
        self,
        vulnerabilities: List[DependencyFinding],
        deprecated: Optional[List[dict]] = None,
        unpinned: Optional[List[dict]] = None,
    ) -> None:
        self._dependency_findings = vulnerabilities or []
        self._deprecated_dependencies = deprecated or []
        self._unpinned_dependencies = unpinned or []

    def add_secret_findings(self, findings: List[SecretFinding]) -> None:
        self._secret_findings = findings or []

    def save(self) -> None:
        payload = self._build_payload()
        html = _render_html(payload)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(html, encoding="utf-8")

    def _build_payload(self) -> dict:
        findings = []
        findings.extend(self._serialize_security_findings())
        findings.extend(self._serialize_dependency_findings())
        findings.extend(self._serialize_secret_findings())
        findings.sort(key=lambda item: SEVERITY_ORDER.get(item.get("severity", DEFAULT_SEVERITY), 5))
        return {"findings": findings, "summary": _build_summary(findings)}

    def _serialize_security_findings(self) -> List[dict]:
        return [
            {
                "type": "check",
                "check_id": _safe_text(finding.check_id),
                "title": _safe_text(finding.title or finding.check_id),
                "severity": _normalize_severity(finding.severity),
                "category": _safe_text(finding.category),
                "resource": _safe_text(finding.resource),
                "evidence": _safe_text(finding.evidence),
                "description": _safe_text(finding.description),
                "risk": _safe_text(finding.risk),
                "remediation": _safe_text(finding.remediation),
                "reference_url": _safe_text(finding.reference_url),
            }
            for finding in self._security_findings
        ]

    def _serialize_dependency_findings(self) -> List[dict]:
        findings = []
        for finding in self._dependency_findings:
            package = _safe_text(finding.package)
            version = _safe_text(finding.version)
            file_path = _safe_text(finding.file_path)
            advisory_id = _safe_text(getattr(finding, "advisory_id", ""))
            cvss_score = getattr(finding, "cvss_score", "")
            findings.append(
                {
                    "type": "dependency",
                    "title": _safe_text(finding.title),
                    "severity": _normalize_severity(finding.severity),
                    "category": DEPENDENCY_CATEGORY,
                    "resource": _safe_text(finding.repository),
                    "evidence": f"{package}@{version} in {file_path}".strip(),
                    "description": f"Advisory: {advisory_id}" if advisory_id else "",
                    "risk": f"CVSS score: {cvss_score}" if cvss_score not in (None, "") else "",
                    "remediation": f"Update {package} to a patched version." if package else "Update to a patched version.",
                    "reference_url": _safe_text(getattr(finding, "url", "")),
                    "package": package,
                    "version": version,
                    "ecosystem": _safe_text(getattr(finding, "ecosystem", "")),
                    "cvss_score": cvss_score,
                    "advisory_id": advisory_id,
                    "file_path": file_path,
                }
            )
        return findings

    def _serialize_secret_findings(self) -> List[dict]:
        findings = []
        for finding in self._secret_findings:
            file_path = _safe_text(finding.file_path)
            line_number = getattr(finding, "line_number", None)
            location = f"{file_path}:{line_number}" if line_number else file_path
            secret_type = _safe_text(finding.secret_type)
            findings.append(
                {
                    "type": "secret",
                    "title": f"Exposed {secret_type}" if secret_type else "Exposed Secret",
                    "severity": "Critical",
                    "category": SECRET_CATEGORY,
                    "resource": _safe_text(finding.repository),
                    "evidence": location,
                    "description": "",
                    "risk": "Exposed credentials can be used to access systems immediately.",
                    "remediation": SECRET_REMEDIATION,
                    "reference_url": "",
                    "secret_type": secret_type,
                    "file_path": file_path,
                    "line_number": line_number,
                }
            )
        return findings


def _build_summary(findings: List[dict]) -> dict:
    by_severity = {}
    by_type = {}
    for finding in findings:
        severity = finding.get("severity") or DEFAULT_SEVERITY
        finding_type = finding.get("type") or "unknown"
        by_severity[severity] = by_severity.get(severity, 0) + 1
        by_type[finding_type] = by_type.get(finding_type, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_type": by_type}


def _normalize_severity(value: Any) -> str:
    if value is None:
        return DEFAULT_SEVERITY
    severity = str(value).strip().capitalize()
    if severity in SEVERITY_ORDER:
        return severity
    return "Unknown" if severity == "" else severity


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _render_html(payload: dict) -> str:
    data_json = json.dumps(payload, indent=2, ensure_ascii=False)
    return HTML_TEMPLATE.replace("__REPORT_JSON__", data_json)


HTML_TEMPLATE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>gitsec — Security Report</title>
<style>
  *, *::before, *::after { box-sizing: border-box; }
  :root {
    --bg: #04110F;
    --surface: #071816;
    --surface-2: #0A201C;
    --surface-3: #0F2B24;
    --border: rgba(141,214,196,.24);
    --border-strong: rgba(141,214,196,.42);
    --text: #EAF5F0;
    --muted: #9EC7B6;
    --muted-2: #7EA293;
    --accent: #67E3AF;
    --accent-2: #8DD6C4;
    --accent-soft: rgba(103,227,175,.12);
    --crit: #E94B4B;
    --crit-t: #FF9A9A;
    --crit-bg: rgba(233,75,75,.13);
    --high: #F08A24;
    --high-t: #FFBE77;
    --high-bg: rgba(240,138,36,.13);
    --med: #E0BE42;
    --med-t: #F3DE8A;
    --med-bg: rgba(224,190,66,.13);
    --low: #4C93F0;
    --low-t: #95C0FF;
    --low-bg: rgba(76,147,240,.13);
    --info: #9CA3AF;
    --info-t: #D1D5DB;
    --info-bg: rgba(156,163,175,.14);
    --sans: Arial, Helvetica, 'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --shadow: 0 18px 50px rgba(0,0,0,.26);
  }

  html, body {
    min-height: 100%;
    margin: 0;
    background:
      radial-gradient(circle at 0 0, rgba(24,226,153,.055), transparent 28%),
      radial-gradient(circle at 100% 0, rgba(103,227,175,.04), transparent 26%),
      var(--bg);
    background-attachment: fixed;
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
  }
  body { display: flex; flex-direction: column; overflow-x: hidden; }
  a { color: var(--accent-2); text-decoration: none; word-break: break-word; }
  a:hover { color: #58A6FF; text-decoration: underline; }

  .header {
    min-height: 88px;
    padding: 24px 32px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(4,17,15,.95);
    box-shadow: 0 14px 32px rgba(0,0,0,.18);
  }
  .logo { display: flex; align-items: center; gap: 14px; }
  .logo-icon {
    width: 46px;
    height: 46px;
    border-radius: 13px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 1px solid rgba(103,227,175,.30);
    background: linear-gradient(180deg, rgba(103,227,175,.08), rgba(103,227,175,.035));
  }
  .logo-name { font-size: 24px; font-weight: 800; line-height: 1; letter-spacing: -.04em; color: #FFFFFF; }
  .logo-sub { margin-top: 6px; font-size: 13px; font-weight: 700; color: #9FF7D5; }
  .meta {
    color: #CBE0D7;
    font-size: 12px;
    font-family: var(--mono);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 9px 14px;
    background: rgba(103,227,175,.055);
  }

  .main { display: flex; flex: 1; min-height: 0; }
  .list-pane { flex: 1; min-width: 0; padding: 28px 32px 36px; }
  .detail-pane {
    display: none;
    position: fixed;
    top: 0;
    right: 0;
    z-index: 50;
    width: min(440px, 100vw);
    height: 100vh;
    overflow-y: auto;
    padding: 22px 24px 30px;
    border-left: 1px solid var(--border-strong);
    background: #04110F;
    box-shadow: -18px 0 42px rgba(0,0,0,.32);
  }
  .detail-pane.open { display: block; }
  body.detail-open .list-pane { padding-right: 472px; }

  .report-tabs {
    display: flex;
    width: fit-content;
    gap: 6px;
    padding: 6px;
    margin: 0 0 20px 0;
    border: 1px solid var(--border);
    border-radius: 999px;
    background: rgba(255,255,255,.018);
  }
  .report-tab-btn, .filter-btn, .view-btn, .close-btn {
    border: 1px solid transparent;
    border-radius: 999px;
    background: transparent;
    color: rgba(234,245,240,.75);
    cursor: pointer;
    font-family: var(--sans);
    font-weight: 800;
    transition: background .14s, border-color .14s, color .14s;
  }
  .report-tab-btn { padding: 11px 20px; font-size: 13px; }
  .report-tab-btn.active, .filter-btn.active, .view-btn.active {
    color: var(--text);
    background: var(--accent-soft);
    border-color: rgba(103,227,175,.36);
  }

  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  .control-panel {
    margin-bottom: 14px;
    padding: 18px;
    border: 1px solid var(--border);
    border-radius: 22px;
    background: rgba(7,24,22,.92);
    box-shadow: 0 8px 22px rgba(0,0,0,.16);
  }
  .control-title {
    color: rgba(234,245,240,.78);
    font-size: 12px;
    font-weight: 900;
    letter-spacing: .10em;
    text-transform: uppercase;
    margin-bottom: 12px;
  }
  .filters {
    display: grid;
    grid-template-columns: minmax(210px, 300px) minmax(390px, 1fr) minmax(320px, .78fr);
    gap: 10px;
    align-items: center;
  }
  .filters input {
    width: 100%;
    height: 44px;
    min-width: 0;
    padding: 0 13px;
    border: 1px solid rgba(141,214,196,.22);
    border-radius: 13px;
    outline: none;
    background: rgba(255,255,255,.035);
    color: var(--text);
    font-size: 13px;
  }
  .filters input:focus { border-color: rgba(103,227,175,.52); box-shadow: 0 0 0 3px rgba(103,227,175,.10); }
  .filter-group {
    height: 44px;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 7px;
    overflow: hidden;
    padding: 7px 9px;
    border: 1px solid rgba(141,214,196,.20);
    border-radius: 13px;
    background: rgba(255,255,255,.018);
  }
  .filter-label {
    flex: 0 0 auto;
    color: #F2FFF9;
    font-size: 12px;
    font-weight: 900;
    letter-spacing: .055em;
    text-transform: uppercase;
    white-space: nowrap;
    text-decoration: underline;
    text-underline-offset: 4px;
  }
  .filter-btn { flex: 0 1 auto; padding: 7px 9px; font-size: 11px; white-space: nowrap; }
  .filter-btn.active-crit { background: var(--crit-bg); border-color: rgba(233,75,75,.50); color: var(--crit-t); }
  .filter-btn.active-high { background: var(--high-bg); border-color: rgba(240,138,36,.50); color: var(--high-t); }
  .filter-btn.active-medi { background: var(--med-bg); border-color: rgba(224,190,66,.48); color: var(--med-t); }
  .filter-btn.active-low { background: var(--low-bg); border-color: rgba(76,147,240,.48); color: var(--low-t); }
  .filter-btn.active-unkn { background: var(--info-bg); border-color: rgba(156,163,175,.40); color: var(--info-t); }

  .result-count { color: var(--muted); margin: 12px 2px 10px; font-size: 13px; font-weight: 650; }
  .table {
    border: 1px solid var(--border);
    border-radius: 16px;
    overflow: hidden;
    background: rgba(7,24,22,.94);
    box-shadow: var(--shadow);
  }
  .table-head, .row {
    display: grid;
    grid-template-columns: minmax(106px,.8fr) minmax(116px,.9fr) minmax(280px,3fr) minmax(140px,1fr);
    align-items: center;
    gap: 12px;
  }
  .table-head { padding: 12px 16px; border-bottom: 1px solid var(--border); background: rgba(103,227,175,.035); }
  .table-head span { color: var(--muted-2); font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; }
  .row { min-height: 68px; padding: 15px 16px; border-bottom: 1px solid rgba(141,214,196,.12); border-left: 3px solid transparent; cursor: pointer; }
  .row:last-child { border-bottom: 0; }
  .row:hover { background: rgba(103,227,175,.045); }
  .row.selected { border-left-color: var(--accent); background: rgba(103,227,175,.07); }
  .row-title { color: #F4FFFA; font-size: 15px; font-weight: 700; line-height: 1.35; }
  .row-cat, .row-res { color: var(--muted); font-size: 12px; line-height: 1.35; }
  .row-cat { margin-top: 5px; }
  .row-res { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--mono); }
  .empty { padding: 42px; text-align: center; color: var(--muted); }

  .sev-badge, .type-badge {
    min-width: 104px;
    height: 34px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    padding: 0 11px;
    border: 1px solid rgba(141,214,196,.22);
    border-radius: 999px;
    font-size: 12px;
    font-weight: 750;
    white-space: nowrap;
  }
  .type-badge { min-width: 112px; }
  .dot { width: 7px; height: 7px; border-radius: 999px; flex: 0 0 auto; }
  .sev-Critical { background: var(--crit-bg); border-color: rgba(233,75,75,.50); color: var(--crit-t); }
  .sev-High { background: var(--high-bg); border-color: rgba(240,138,36,.50); color: var(--high-t); }
  .sev-Medium { background: var(--med-bg); border-color: rgba(224,190,66,.46); color: var(--med-t); }
  .sev-Low { background: var(--low-bg); border-color: rgba(76,147,240,.46); color: var(--low-t); }
  .sev-Unknown { background: var(--info-bg); border-color: rgba(156,163,175,.36); color: var(--info-t); }
  .sev-badge.clickable, .severity-link { cursor: pointer; transition: transform .12s ease, border-color .12s ease, background .12s ease; }
  .sev-badge.clickable:hover, .severity-link:hover { transform: translateY(-1px); border-color: rgba(255,255,255,.36); text-decoration: none; }
  .severity-link { color: inherit; font-weight: 800; border-bottom: 1px dotted rgba(141,214,196,.45); }
  .type-check { background: rgba(59,130,246,.12); border-color: rgba(147,197,253,.30); color: #BFDBFE; }
  .type-dependency { background: rgba(6,95,70,.16); border-color: rgba(110,231,183,.34); color: #A7F3D0; }
  .type-secret { background: rgba(127,29,29,.16); border-color: rgba(252,165,165,.34); color: #FECACA; }

  .close-btn { margin: 0 0 18px 0; padding: 8px 12px; border-color: var(--border); background: rgba(255,255,255,.025); color: var(--text); }
  .detail-badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }
  .detail-pane .sev-badge, .detail-pane .type-badge { min-width: 112px; }
  .detail-title { font-size: 18px; font-weight: 700; line-height: 1.35; margin-bottom: 8px; }
  .detail-id { color: var(--muted); font-size: 13px; margin-bottom: 18px; }
  .section { margin-bottom: 17px; }
  .section-label { color: rgba(234,245,240,.78); font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }
  .code-block, .risk-block, .fix-block, .warn-block {
    border: 1px solid rgba(141,214,196,.26);
    border-radius: 13px;
    background: rgba(255,255,255,.022);
    padding: 12px 13px;
    color: rgba(255,255,255,.92);
    line-height: 1.55;
    word-break: break-word;
  }
  .code-block { font-family: var(--mono); font-size: 12px; }
  .risk-block { border-color: rgba(240,138,36,.30); color: #FFD3A8; background: rgba(240,138,36,.05); }
  .fix-block { border-color: rgba(103,227,175,.30); color: #CFFBE7; background: rgba(103,227,175,.045); }
  .warn-block { border-color: rgba(233,75,75,.34); color: #FFC7C7; background: rgba(233,75,75,.06); }

  .summary-top-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px; }
  .summary-grid { display: grid; grid-template-columns: minmax(330px, .9fr) minmax(360px, 1.1fr); gap: 18px; margin-bottom: 18px; }
  .summary-card, .summary-panel {
    background: rgba(7,24,22,.94);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 18px 20px;
    box-shadow: 0 8px 22px rgba(0,0,0,.16);
  }
  .summary-card-label, .summary-section-label { color: rgba(234,245,240,.70); font-size: 12px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }
  .summary-card-value { font-size: 34px; font-weight: 800; color: #FFFFFF; line-height: 1; }
  .summary-card-sub { color: #8DD6C4; font-size: 13px; margin-top: 8px; }
  .summary-section-head { display: flex; justify-content: space-between; align-items: center; gap: 14px; flex-wrap: wrap; margin-bottom: 16px; }
  .summary-section-subtitle { color: #8DD6C4; font-size: 13px; margin-top: 2px; }
  .summary-list { display: grid; gap: 11px; }
  .summary-row { display: grid; grid-template-columns: 12px minmax(120px,1fr) auto auto; align-items: center; gap: 10px; font-size: 14px; }
  .summary-percent { color: #8DD6C4; font-weight: 800; }
  .summary-count { color: #FFFFFF; font-weight: 900; }
  .legend-dot { width: 10px; height: 10px; border-radius: 999px; }
  .pie-wrap { display: grid; grid-template-columns: 190px 1fr; gap: 22px; align-items: center; }
  .pie-chart { width: 190px; height: 190px; border-radius: 50%; border: 1px solid rgba(255,255,255,.14); box-shadow: inset 0 0 0 31px var(--bg); background: conic-gradient(#9CA3AF 0deg 360deg); }

  .view-switch {
    display: inline-flex;
    gap: 14px;
    align-items: center;
    padding: 8px;
    border: 1px solid rgba(141,214,196,.26);
    border-radius: 999px;
    background: rgba(255,255,255,.018);
  }
  .view-btn { min-width: 112px; padding: 11px 18px; font-size: 14px; }
  .triage-group-results { display: grid; gap: 10px; max-height: 760px; overflow-y: auto; padding-right: 6px; }
  .summary-details {
    border: 1px solid rgba(141,214,196,.20);
    border-radius: 14px;
    overflow: hidden;
    background: rgba(255,255,255,.015);
  }
  .summary-details summary {
    cursor: pointer;
    list-style: none;
    padding: 14px 16px;
    display: flex;
    justify-content: space-between;
    gap: 12px;
    color: #F4FFFA;
    font-weight: 800;
  }
  .summary-details summary::-webkit-details-marker { display: none; }
  .summary-details-body { border-top: 1px solid rgba(141,214,196,.14); padding: 13px 16px; color: #8DD6C4; font-size: 13px; line-height: 1.55; }
  .summary-line { height: 1px; background: rgba(141,214,196,.14); margin: 10px 0; }
  .group-body-grid { display: grid; grid-template-columns: minmax(220px,.8fr) minmax(260px,1.2fr); gap: 18px; }
  .group-field-label { color: rgba(234,245,240,.72); font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 8px; }
  .group-muted { color: #8DD6C4; }
  .group-preview-note { color: rgba(234,245,240,.68); font-size: 12px; margin: -2px 0 10px; }
  .summary-mini-list { margin: 0; padding-left: 18px; }
  .summary-mini-list li { margin-bottom: 6px; }
  .show-all-btn {
    margin-top: 12px;
    border: 1px solid rgba(141,214,196,.30);
    background: rgba(103,227,175,.08);
    color: #EAF5F0;
    border-radius: 999px;
    padding: 9px 13px;
    font-size: 12px;
    font-weight: 800;
    cursor: pointer;
  }
  .show-all-btn:hover { background: rgba(103,227,175,.14); border-color: rgba(141,214,196,.45); }
  .group-all-findings { margin-top: 12px; display: grid; gap: 9px; }
  .group-all-findings[hidden] { display: none; }
  .group-finding-item {
    border: 1px solid rgba(141,214,196,.16);
    border-radius: 12px;
    padding: 10px 12px;
    background: rgba(255,255,255,.014);
  }
  .group-finding-title { color: #F4FFFA; font-weight: 700; line-height: 1.35; }
  .group-finding-meta { color: #8DD6C4; font-size: 12px; margin-top: 5px; line-height: 1.45; }


  @media (max-width: 1260px) {
    body.detail-open .list-pane { padding-right: 32px; }
    .filters, .summary-top-grid, .summary-grid, .group-body-grid { grid-template-columns: 1fr; }
    .filter-group { height: auto; min-height: 44px; flex-wrap: wrap; overflow: visible; }
    .pie-wrap { grid-template-columns: 1fr; }
  }
  @media (max-width: 760px) {
    .header { align-items: flex-start; flex-direction: column; }
    .list-pane { padding: 22px 18px 28px; }
    .table-head { display: none; }
    .row { grid-template-columns: 1fr; gap: 8px; }
    .view-switch { width: 100%; justify-content: center; flex-wrap: wrap; border-radius: 22px; }
    .view-btn { min-width: auto; }
  }
</style>
</head>
<body>
<header class="header">
  <div class="logo">
    <div class="logo-icon">
      <svg width="28" height="28" viewBox="0 0 510 522" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <path d="M382.5 315.169 382.5 153C382.5 138.916 371.084 127.5 357 127.5L355.717 127.5C348.955 127.5 342.47 130.189 337.689 134.97L134.97 337.689C130.189 342.47 127.5 348.955 127.5 355.717L127.5 521.461 0 521.461 0 355.717C0.000274523 315.139 16.1189 276.222 44.8118 247.53L247.53 44.8118C276.222 16.1189 315.139 0.000272506 355.717 0L357 0C441.499 0 510 68.5004 510 153L510 315.169C510 399.668 441.499 468.169 357 468.169L195.691 468.169 195.691 340.669 357 340.669C371.084 340.669 382.5 329.252 382.5 315.169Z" fill="#18E299"/>
      </svg>
    </div>
    <div>
      <div class="logo-name">gitsec</div>
      <div class="logo-sub">security posture report</div>
    </div>
  </div>
  <div class="meta" id="meta-info">—</div>
</header>

<main class="main">
  <section class="list-pane">
    <nav class="report-tabs" aria-label="Report tabs">
      <button class="report-tab-btn active" data-tab="findings" onclick="switchTab(this)">Findings</button>
      <button class="report-tab-btn" data-tab="summary" onclick="switchTab(this)">Summary</button>
    </nav>

    <section id="findings-panel" class="tab-panel active">
      <div class="control-panel">
        <div class="control-title">Triage Controls</div>
        <div class="filters">
          <input id="search" placeholder="search findings, repo, package..." oninput="applyFilters()"/>
          <div class="filter-group">
            <span class="filter-label">Severity</span>
            <button class="filter-btn active" data-sev="All" onclick="setSev(this)">All</button>
            <button class="filter-btn" data-sev="Critical" onclick="setSev(this)">Critical</button>
            <button class="filter-btn" data-sev="High" onclick="setSev(this)">High</button>
            <button class="filter-btn" data-sev="Medium" onclick="setSev(this)">Medium</button>
            <button class="filter-btn" data-sev="Low" onclick="setSev(this)">Low</button>
            <button class="filter-btn" data-sev="Unknown" onclick="setSev(this)">Unknown</button>
          </div>
          <div class="filter-group">
            <span class="filter-label">Type</span>
            <button class="filter-btn active" data-type="All" onclick="setType(this)">All</button>
            <button class="filter-btn" data-type="check" onclick="setType(this)">Checks</button>
            <button class="filter-btn" data-type="dependency" onclick="setType(this)">Dependencies</button>
            <button class="filter-btn" data-type="secret" onclick="setType(this)">Secrets</button>
          </div>
        </div>
      </div>

      <div class="result-count" id="result-count"></div>
      <div class="table">
        <div class="table-head"><span>Severity</span><span>Type</span><span>Finding</span><span>Resource</span></div>
        <div id="rows"></div>
      </div>
    </section>

    <section id="summary-panel" class="tab-panel"></section>
  </section>

  <aside class="detail-pane" id="detail">
    <button class="close-btn" onclick="closeDetail()">← close</button>
    <div id="detail-content"></div>
  </aside>
</main>

<script>
const REPORT = __REPORT_JSON__;
const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
const TYPE_ORDER = ['check', 'dependency', 'secret', 'unknown'];
const SEVERITY_COLORS = {Critical:'#E94B4B', High:'#F08A24', Medium:'#E0BE42', Low:'#4C93F0', Unknown:'#9CA3AF'};
let activeSev = 'All';
let activeType = 'All';
let summaryGroupMode = 'finding';
let selectedIdx = null;

function initializeReport() {
  document.getElementById('meta-info').textContent = `${(REPORT.findings || []).length} findings · ${new Date().toLocaleDateString('en-GB')}`;
  applyFilters();
}

document.addEventListener('DOMContentLoaded', initializeReport);

function switchTab(btn) {
  const target = btn.dataset.tab;
  document.querySelectorAll('.report-tab-btn').forEach(item => item.classList.toggle('active', item === btn));
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
  document.getElementById(`${target}-panel`).classList.add('active');
  if (target === 'summary') renderSummaryDashboard();
  if (target === 'summary') closeDetail(false);
}

function setSev(btn) {
  setSeverityValue(btn.dataset.sev || 'All');
}

function syncSeverityButtons() {
  document.querySelectorAll('[data-sev]').forEach(item => {
    item.className = 'filter-btn';
    if (item.dataset.sev === activeSev) {
      item.classList.add(activeSev === 'All' ? 'active' : 'active-' + activeSev.toLowerCase().slice(0, 4));
    }
  });
}

function setSeverityValue(severity) {
  activeSev = severity || 'All';
  syncSeverityButtons();
  applyFilters();
}

function filterBySeverity(event, severity) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const nextSeverity = activeSev === severity ? 'All' : (severity || 'All');
  setSeverityValue(nextSeverity);
}

function setType(btn) {
  activeType = btn.dataset.type;
  document.querySelectorAll('[data-type]').forEach(item => item.className = 'filter-btn');
  btn.classList.add('active');
  applyFilters();
}

function setSummaryGroupMode(btn) {
  summaryGroupMode = btn.dataset.mode;

  // No group is intended as a neutral/raw view, so reset only the severity filter
  // when entering it. Search and Type filters remain active because they are explicit
  // triage filters, but the user should not be stuck seeing only Critical findings.
  if (summaryGroupMode === 'flat' && activeSev !== 'All') {
    activeSev = 'All';
    syncSeverityButtons();
  }

  document.querySelectorAll('[data-summary-mode]').forEach(item => item.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

function currentFindings() {
  return filteredFindings({ignoreSeverity: false});
}

function findingsIgnoringSeverity() {
  return filteredFindings({ignoreSeverity: true});
}

function filteredFindings(options = {}) {
  const q = document.getElementById('search')?.value.trim().toLowerCase() || '';
  return (REPORT.findings || []).filter(f => {
    if (!options.ignoreSeverity && activeSev !== 'All' && normalizeSeverity(f.severity) !== activeSev) return false;
    if (activeType !== 'All' && f.type !== activeType) return false;
    if (!q) return true;
    return [f.title, f.resource, f.category, f.evidence, f.package, f.version, f.secret_type, f.check_id]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(q);
  });
}

function applyFilters() {
  const findings = currentFindings();
  const total = (REPORT.findings || []).length;
  document.getElementById('result-count').textContent = `showing ${findings.length} of ${total} findings`;
  renderRows(findings);
  renderSummaryDashboard();
}

function renderRows(findings) {
  const rows = document.getElementById('rows');
  if (!findings.length) {
    rows.innerHTML = '<div class="empty">No findings match the current filters.</div>';
    return;
  }
  rows.innerHTML = findings.map(renderRow).join('');
}

function renderRow(f) {
  const idx = (REPORT.findings || []).indexOf(f);
  const selected = selectedIdx === idx ? ' selected' : '';
  return `<div class="row${selected}" onclick="openDetail(${idx})">
    <div>${severityBadge(f.severity)}</div>
    <div>${typeBadge(f.type)}</div>
    <div>
      <div class="row-title">${esc(f.title || 'Untitled finding')}</div>
      <div class="row-cat">${esc(compactEvidence(f) || f.category || '')}</div>
    </div>
    <div class="row-res">${esc(compactResource(f.resource))}</div>
  </div>`;
}

function openDetail(idx) {
  selectedIdx = idx;
  const f = REPORT.findings[idx];
  const isSecret = f.type === 'secret';
  const id = f.check_id || f.advisory_id || f.secret_type || '';
  let html = `<div class="detail-badges">${severityBadge(f.severity)}${typeBadge(f.type)}</div>`;
  if (!isSecret) html += `<div class="detail-title">${esc(f.title || 'Untitled finding')}</div>${id ? `<div class="detail-id">${esc(id)}</div>` : ''}`;
  html += `<div class="section"><div class="section-label">Scope</div><div class="code-block">${esc(compactResource(f.resource))}</div></div>`;
  html += `<div class="section"><div class="section-label">Evidence</div><div class="code-block">${esc(compactEvidence(f) || 'No specific evidence provided')}</div></div>`;
  if (f.risk) html += `<div class="section"><div class="section-label">Risk</div><div class="risk-block">${esc(f.risk)}</div></div>`;
  if (f.type === 'dependency') {
    if (f.package || f.version || f.ecosystem) html += `<div class="section"><div class="section-label">Package</div><div class="code-block">${esc(packageText(f))}</div></div>`;
    if (f.cvss_score !== undefined && String(f.cvss_score) !== '') html += `<div class="section"><div class="section-label">CVSS</div><div class="code-block">${esc(String(f.cvss_score))}</div></div>`;
  }
  if (isSecret) html += `<div class="section"><div class="section-label">Immediate action</div><div class="warn-block">Rotate the credential immediately and remove it from repository history.</div></div>`;
  if (f.reference_url) html += `<div class="section"><div class="section-label">Reference</div><a href="${esc(f.reference_url)}" target="_blank" rel="noopener noreferrer">${esc(f.reference_url)}</a></div>`;
  document.getElementById('detail-content').innerHTML = html;
  document.getElementById('detail').classList.add('open');
  document.body.classList.add('detail-open');
  renderRows(currentFindings());
}

function closeDetail(refresh = true) {
  selectedIdx = null;
  document.getElementById('detail').classList.remove('open');
  document.body.classList.remove('detail-open');
  if (refresh) renderRows(currentFindings());
}

function renderSummaryDashboard() {
  const panel = document.getElementById('summary-panel');
  if (!panel) return;
  const findings = currentFindings();
  const total = findings.length;
  const allTotal = (REPORT.findings || []).length;
  const repos = unique(findings.map(repoKey));
  const severityBaseFindings = findingsIgnoringSeverity();
  const severityCounts = countBy(severityBaseFindings, f => normalizeSeverity(f.severity));
  const typeCounts = countBy(findings, f => f.type || 'unknown');
  const duplicateGroups = buildGroups(findings, 'finding').filter(g => g.items.length > 1).length;

  panel.innerHTML = `
    <div class="summary-top-grid">
      <div class="summary-card">
        <div class="summary-card-label">Total Findings</div>
        <div class="summary-card-value">${total}</div>
        <div class="summary-card-sub">${total === allTotal ? 'All findings in this scan' : `Filtered from ${allTotal} total`}</div>
      </div>
      <div class="summary-card">
        <div class="summary-card-label">Affected Repositories</div>
        <div class="summary-card-value">${repos.length}</div>
        <div class="summary-card-sub">Unique repositories/resources</div>
      </div>
      <div class="summary-card">
        <div class="summary-card-label">Duplicate Findings</div>
        <div class="summary-card-value">${duplicateGroups}</div>
        <div class="summary-card-sub">Same check/finding appearing more than once</div>
      </div>
    </div>
    <div class="summary-grid">
      <div class="summary-panel">
        <div class="summary-section-label">Severity Distribution</div>
        <div class="pie-wrap">
          <div class="pie-chart" style="background:${severityConicGradient(severityCounts, total)}"></div>
          <div class="summary-list">${summaryRows(severityCounts, SEVERITY_ORDER, true, severityBaseFindings.length)}</div>
        </div>
      </div>
      <div class="summary-panel">
        <div class="summary-section-label">Finding Type Breakdown</div>
        <div class="summary-list">${summaryRows(typeCounts, TYPE_ORDER, false, total)}</div>
      </div>
    </div>
    <div class="summary-panel">
      <div class="summary-section-head">
        <div>
          <div class="summary-section-label">Grouped Findings</div>
        </div>
        <div class="view-switch" aria-label="Remediation grouping">
          <button class="view-btn ${summaryGroupMode === 'finding' ? 'active' : ''}" data-summary-mode="finding" data-mode="finding" onclick="setSummaryGroupMode(this)">By issue</button>
          <button class="view-btn ${summaryGroupMode === 'resource' ? 'active' : ''}" data-summary-mode="resource" data-mode="resource" onclick="setSummaryGroupMode(this)">By repo</button>
          <button class="view-btn ${summaryGroupMode === 'flat' ? 'active' : ''}" data-summary-mode="flat" data-mode="flat" onclick="setSummaryGroupMode(this)">No group</button>
        </div>
      </div>
      <div class="triage-group-results">${renderSummaryGroups(findings, summaryGroupMode)}</div>
    </div>`;
}

function renderSummaryGroups(findings, mode) {
  if (!findings.length) return '<div class="summary-details-body">No findings match the current filters.</div>';
  if (mode === 'flat') {
    return findings.slice(0, 180).map(f => {
      const label = `${normalizeSeverity(f.severity)} · ${typeLabel(f.type)}`;
      return `<details class="summary-details">
        <summary><span>${esc(f.title || 'Untitled finding')}</span><span>${esc(label)}</span></summary>
        <div class="summary-details-body">
          <div class="group-body-grid">
            <div><div class="group-field-label">Repository</div><div class="group-muted">${esc(compactResource(f.resource))}</div></div>
            <div><div class="group-field-label">Evidence Preview</div><div class="group-muted">${esc(compactEvidence(f) || 'No specific evidence provided')}</div></div>
          </div>
        </div>
      </details>`;
    }).join('');
  }
  const groups = buildGroups(findings, mode).slice(0, 160);
  return groups.map((group, groupIndex) => {
    const resources = unique(group.items.map(repoKey));
    const severity = highestSeverity(group.items);
    const type = dominantType(group.items);
    const uniqueIssues = unique(group.items.map(findingKey)).length;
    const repeats = Math.max(0, group.items.length - uniqueIssues);
    const evidenceAll = unique(group.items.map(compactEvidence).filter(Boolean));
    const evidencePreview = evidenceAll.slice(0, 6);
    const packagesAll = unique(group.items.map(packageText).filter(Boolean));
    const packagesPreview = packagesAll.slice(0, 3);
    const title = mode === 'resource' ? compactResource(group.title) : group.title;
    const subtitle = mode === 'resource'
      ? `${group.items.length} total findings · ${uniqueIssues} unique issues · ${repeats} repeats grouped`
      : `${resources.length} repositories/resources · ${group.items.length} total findings · ${repeats} repeats grouped`;
    const evidenceNote = `Showing ${Math.min(evidencePreview.length || 0, 6)} evidence examples from ${group.items.length} total findings.`;
    const groupId = `group-${mode}-${groupIndex}`;
    const showAllButton = group.items.length > evidencePreview.length
      ? `<button class="show-all-btn" type="button" onclick="toggleGroupFindings(event, '${groupId}')">Show all findings</button><div class="group-all-findings" id="${groupId}" hidden>${renderDetailedFindingList(group.items)}</div>`
      : '';
    return `<details class="summary-details">
      <summary><span>${esc(title)}</span><span>${clickableSeverityText(severity)} · ${group.items.length} total · ${esc(typeLabel(type))}</span></summary>
      <div class="summary-details-body">
        <div class="group-muted">${esc(subtitle)}</div>
        <div class="summary-line"></div>
        <div class="group-body-grid">
          <div><div class="group-field-label">Repositories</div>${renderList(resources.map(compactResource).slice(0, 14))}</div>
          <div><div class="group-field-label">Evidence Preview</div><div class="group-preview-note">${esc(evidenceNote)}</div>${packagesPreview.length ? `<div class="group-muted" style="margin-bottom:10px">${esc(packagesPreview.join(' · '))}</div>` : ''}${renderList(evidencePreview)}${showAllButton}</div>
        </div>
      </div>
    </details>`;
  }).join('');
}

function buildGroups(findings, mode) {
  const keyFn = mode === 'resource' ? repoKey : findingKey;
  return Object.entries(groupBy(findings, keyFn))
    .map(([key, items]) => ({title: key, items}))
    .sort((a, b) => b.items.length - a.items.length || a.title.localeCompare(b.title));
}

function renderList(items) {
  if (!items || !items.length) return '<div class="group-muted">No specific evidence provided.</div>';
  return `<ul class="summary-mini-list">${items.map(item => `<li>${esc(item)}</li>`).join('')}</ul>`;
}

function renderDetailedFindingList(items) {
  const grouped = Object.values(groupBy(items || [], detailedFindingKey))
    .map(group => ({item: group[0], count: group.length}))
    .sort((a, b) => severityRank(a.item.severity) - severityRank(b.item.severity) || (a.item.title || '').localeCompare(b.item.title || ''));

  return grouped.map(({item: f, count}) => {
    const repeatText = count > 1 ? ` · ${count} occurrences` : '';
    return `<div class="group-finding-item">
      <div class="group-finding-title">${esc(f.title || 'Untitled finding')}</div>
      <div class="group-finding-meta">${esc(normalizeSeverity(f.severity))} · ${esc(typeLabel(f.type))} · ${esc(compactResource(f.resource))}${esc(repeatText)}</div>
      <div class="group-finding-meta">${esc(compactEvidence(f) || 'No specific evidence provided')}</div>
    </div>`;
  }).join('');
}

function toggleGroupFindings(event, groupId) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const panel = document.getElementById(groupId);
  if (!panel) return;
  const shouldShow = panel.hidden;
  panel.hidden = !shouldShow;
  const button = event?.currentTarget;
  if (button) button.textContent = shouldShow ? 'Show preview only' : 'Show all findings';
}

function summaryRows(counts, order, isSeverity, total) {
  const entries = Object.entries(counts || {})
    .filter(([, count]) => count > 0)
    .sort((a, b) => sortByOrder(a[0], b[0], order));
  if (!entries.length) return '<div class="group-muted">No data available.</div>';
  return entries.map(([key, count]) => {
    const label = isSeverity ? key : typeLabel(key);
    const color = isSeverity ? (SEVERITY_COLORS[key] || SEVERITY_COLORS.Unknown) : '#8DD6C4';
    const labelHtml = isSeverity ? clickableSeverityText(key) : esc(label);
    const percent = total ? ((count / total) * 100).toFixed(1) : '0.0';
    return `<div class="summary-row"><span class="legend-dot" style="background:${color}"></span><span>${labelHtml}</span><span class="summary-percent">${percent}%</span><span class="summary-count">${count}</span></div>`;
  }).join('');
}

function severityConicGradient(counts, total) {
  if (!total) return 'conic-gradient(#9CA3AF 0deg 360deg)';
  let start = 0;
  const parts = SEVERITY_ORDER.map(sev => {
    const count = counts[sev] || 0;
    const end = start + (count / total) * 360;
    const part = `${SEVERITY_COLORS[sev] || SEVERITY_COLORS.Unknown} ${start}deg ${end}deg`;
    start = end;
    return count ? part : null;
  }).filter(Boolean);
  return `conic-gradient(${parts.join(', ')})`;
}

function findingKey(f) {
  if (f.type === 'dependency') {
    const title = normalizeTitle(f.title || f.advisory_id || f.reference_url || 'dependency vulnerability');
    const pkg = (f.package || '').toLowerCase();
    const eco = (f.ecosystem || '').toLowerCase();
    return [pkg, title, eco].filter(Boolean).join(' · ');
  }
  if (f.type === 'secret') return f.secret_type || f.title || 'Secret finding';
  return f.check_id || f.title || 'Check finding';
}

function normalizeTitle(value) {
  return String(value || '')
    .replace(/\b(GHSA|PYSEC|CVE)-[A-Z0-9-]+\b/ig, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function repoKey(f) { return compactResource(f.resource || 'Unknown resource'); }
function normalizeSeverity(severity) {
  const value = String(severity || 'Unknown');
  return SEVERITY_ORDER.includes(value) ? value : 'Unknown';
}
function detailedFindingKey(f) {
  return [
    findingKey(f),
    compactResource(f.resource),
    compactEvidence(f),
    packageText(f),
    normalizeSeverity(f.severity),
    typeLabel(f.type)
  ].filter(Boolean).join(' · ').toLowerCase();
}
function compactEvidence(f) {
  if (!f) return '';
  const raw = f.type === 'secret' ? secretLocation(f) : (f.evidence || f.file_path || '');
  if (!raw) return '';
  let value = String(raw);
  const resource = String(f.resource || '').replace(/^repo\//, '');
  if (resource) {
    value = value.replace(new RegExp('^' + escapeRegex(resource) + '\\s*[—:-]\\s*'), '');
    value = value.replace(new RegExp('^repo/' + escapeRegex(resource) + '\\s*[—:-]\\s*'), '');
  }
  return value;
}
function secretLocation(f) { const path = f.file_path || f.evidence || ''; return f.line_number ? `${path}:${f.line_number}` : path; }
function packageText(f) { if (!f || !f.package) return ''; const version = f.version ? `@${f.version}` : ''; const ecosystem = f.ecosystem ? ` (${f.ecosystem})` : ''; return `${f.package}${version}${ecosystem}`; }
function compactResource(resource) { return String(resource || 'Unknown resource').replace(/^repo\//, ''); }
function highestSeverity(items) { return normalizeSeverity((items || []).slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0]?.severity); }
function severityRank(severity) { const rank = SEVERITY_ORDER.indexOf(normalizeSeverity(severity)); return rank === -1 ? 999 : rank; }
function dominantType(items) { const counts = countBy(items || [], f => f.type || 'unknown'); return Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] || 'unknown'; }
function severityBadge(severity) {
  const sev = normalizeSeverity(severity);
  return `<span class="sev-badge clickable sev-${esc(sev)}" role="button" title="Filter by ${esc(sev)} severity. Click again to reset." onclick="filterBySeverity(event, '${esc(sev)}')"><span class="dot" style="background:${SEVERITY_COLORS[sev] || SEVERITY_COLORS.Unknown}"></span>${esc(sev)}</span>`;
}
function clickableSeverityText(severity) {
  const sev = normalizeSeverity(severity);
  return `<span class="severity-link" role="button" title="Filter by ${esc(sev)} severity. Click again to reset." onclick="filterBySeverity(event, '${esc(sev)}')">${esc(sev)}</span>`;
}
function typeBadge(type) { const raw = type || 'unknown'; return `<span class="type-badge type-${esc(raw)}">${esc(typeLabel(raw))}</span>`; }
function typeLabel(type) { return {check: 'Checks', dependency: 'Dependencies', secret: 'Secrets'}[type] || labelize(type); }
function labelize(value) { return String(value || 'unknown').replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()); }
function groupBy(items, keyFn) { return (items || []).reduce((acc, item) => { const key = keyFn(item) || 'Unknown'; if (!acc[key]) acc[key] = []; acc[key].push(item); return acc; }, {}); }
function countBy(items, keyFn) { return (items || []).reduce((acc, item) => { const key = keyFn(item) || 'Unknown'; acc[key] = (acc[key] || 0) + 1; return acc; }, {}); }
function unique(items) { return [...new Set((items || []).filter(Boolean))]; }
function sortByOrder(a, b, order) { const ai = order.indexOf(a); const bi = order.indexOf(b); return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi) || a.localeCompare(b); }
function escapeRegex(value) { return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
function esc(value) { if (value === null || value === undefined) return ''; return String(value).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
</script>
</body>
</html>
'''
