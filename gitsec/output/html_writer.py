import json
from pathlib import Path
from typing import List, Optional
 
from ..models.finding import DependencyFinding, Finding, SecretFinding
 
 
class HtmlReportWriter:
 
    def __init__(self, output_path: Path):
        self.output_path = output_path
        self._security: List[Finding] = []
        self._dependencies: List[DependencyFinding] = []
        self._deprecated: List[dict] = []
        self._unpinned: List[dict] = []
        self._secrets: List[SecretFinding] = []
 
    def add_security_findings(self, findings: List[Finding]) -> None:
        self._security = [f for f in findings if not f.is_error]
 
    def add_dependency_findings(
        self,
        vulnerabilities: List[DependencyFinding],
        deprecated: Optional[List[dict]] = None,
        unpinned: Optional[List[dict]] = None,
    ) -> None:
        self._dependencies = vulnerabilities or []
        self._deprecated = deprecated or []
        self._unpinned = unpinned or []
 
    def add_secret_findings(self, findings: List[SecretFinding]) -> None:
        self._secrets = findings
 
    def save(self) -> None:
        payload = self._build_payload()
        html = _render_html(payload)
        self.output_path.write_text(html, encoding="utf-8")
 
    def _build_payload(self) -> dict:
        findings = []
 
        for f in self._security:
            findings.append({
                "type": "check",
                "check_id": f.check_id,
                "title": f.title or f.check_id,
                "severity": f.severity or "Info",
                "category": f.category or "",
                "resource": f.resource,
                "evidence": f.evidence,
                "description": f.description or "",
                "risk": f.risk or "",
                "remediation": f.remediation or "",
                "reference_url": f.reference_url or "",
            })
 
        for f in self._dependencies:
            findings.append({
                "type": "dependency",
                "title": f.title,
                "severity": f.severity.capitalize() if f.severity else "Info",
                "category": "Dependency Vulnerability",
                "resource": f.repository,
                "evidence": f"{f.package}@{f.version} in {f.file_path}",
                "description": f"Advisory: {f.advisory_id}",
                "risk": f"CVSS score: {f.cvss_score}",
                "remediation": f"Update {f.package} to a patched version.",
                "reference_url": f.url,
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "cvss_score": f.cvss_score,
            })
 
        for f in self._secrets:
            findings.append({
                "type": "secret",
                "title": f"Exposed {f.secret_type}",
                "severity": "Critical",
                "category": "Secrets",
                "resource": f.repository,
                "evidence": f"{f.file_path}" + (f":{f.line_number}" if f.line_number else ""),
                "description": f"A {f.secret_type} was detected in the repository.",
                "risk": "Exposed credentials can be used to access systems immediately.",
                "remediation": "Rotate this credential immediately. Remove from repo history.",
                "reference_url": "",
                "secret_type": f.secret_type,
                "file_path": f.file_path,
                "line_number": f.line_number,
            })
 
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda x: order.get(x.get("severity", "Info"), 4))
 
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
 
        type_counts = {}
        for f in findings:
            t = f.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
 
        return {
            "findings": findings,
            "summary": {
                "total": len(findings),
                "by_severity": counts,
                "by_type": type_counts,
            },
        }
 
 
def _render_html(payload: dict) -> str:
    data_json = json.dumps(payload, indent=2)
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>gitsec — Security Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #080a10; --bg2: #0a0c14; --bg3: #0d0f18;
    --border: #151820; --border2: #1e2130;
    --text: #d4d8e8; --muted: #555a6e;
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Inter', system-ui, sans-serif;
    --crit: #ff4444; --crit-t: #ff7070; --crit-bg: #1e0a0a;
    --high: #ff8c00; --high-t: #ffaa40; --high-bg: #1e1208;
    --med:  #4488ff; --med-t:  #6aa3ff; --med-bg:  #0a1020;
    --low:  #44cc77; --low-t:  #66dd99; --low-bg:  #0a1a0e;
    --info: #888aaa; --info-t: #aaaac8; --info-bg: #12121e;
  }}
  html, body {{ height: 100%; background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 14px; }}
  a {{ color: var(--med-t); }}
  .header {{
    background: var(--bg2); border-bottom: 1px solid var(--border);
    padding: 14px 28px; display: flex; align-items: center;
    justify-content: space-between; flex-wrap: wrap; gap: 12px;
  }}
  .logo {{ display: flex; align-items: center; gap: 10px; }}
  .logo-icon {{ width: 30px; height: 30px; border-radius: 6px;
    background: linear-gradient(135deg, #7c6af7, #4488ff);
    display: flex; align-items: center; justify-content: center; font-size: 15px; }}
  .logo-name {{ font-size: 15px; font-weight: 700; color: #eee; }}
  .logo-sub  {{ font-size: 11px; color: var(--muted); font-family: var(--mono); }}
  .meta {{ font-family: var(--mono); font-size: 11px; color: var(--muted); text-align: right; }}
  .main {{ display: flex; height: calc(100vh - 57px); overflow: hidden; }}
  .list-pane {{ flex: 1; overflow-y: auto; padding: 20px 24px; min-width: 0; }}
  .detail-pane {{
    width: 420px; flex-shrink: 0; overflow-y: auto;
    background: var(--bg2); border-left: 1px solid var(--border);
    padding: 24px; display: none;
  }}
  .detail-pane.open {{ display: block; }}
  .cards {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{
    background: var(--bg3); border: 1px solid var(--border2);
    border-radius: 8px; padding: 12px 16px; flex: 1; min-width: 90px;
  }}
  .card-num   {{ font-family: var(--mono); font-size: 26px; font-weight: 800; line-height: 1; }}
  .card-label {{ font-size: 10px; color: var(--muted); margin-top: 4px;
    font-weight: 600; text-transform: uppercase; letter-spacing: .08em; }}
  .filters {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }}
  .filters input {{
    background: var(--bg3); border: 1px solid var(--border2); color: var(--text);
    border-radius: 4px; padding: 5px 10px; font-size: 12px;
    font-family: var(--mono); outline: none; width: 200px;
  }}
  .filters input:focus {{ border-color: var(--med); }}
  .filter-group {{
    display: flex; align-items: center; gap: 5px;
    background: var(--bg3); border: 1px solid var(--border2);
    border-radius: 6px; padding: 5px 10px;
  }}
  .filter-label {{
    font-size: 10px; color: var(--muted); font-weight: 700;
    text-transform: uppercase; letter-spacing: .1em;
    font-family: var(--mono); margin-right: 4px; white-space: nowrap;
  }}
  .filter-btn {{
    background: transparent; border: 1px solid transparent; color: var(--muted);
    border-radius: 4px; padding: 3px 9px; cursor: pointer; font-size: 11px;
    font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
    font-family: var(--mono); transition: all .12s;
  }}
  .filter-btn:hover {{ border-color: var(--med); color: var(--med-t); }}
  .filter-btn.active      {{ background: #4488ff22; border-color: var(--med);  color: var(--med-t); }}
  .filter-btn.active-crit {{ background: #ff444422; border-color: var(--crit); color: var(--crit-t); }}
  .filter-btn.active-high {{ background: #ff8c0022; border-color: var(--high); color: var(--high-t); }}
  .filter-btn.active-med  {{ background: #4488ff22; border-color: var(--med);  color: var(--med-t); }}
  .filter-btn.active-low  {{ background: #44cc7722; border-color: var(--low);  color: var(--low-t); }}
  .result-count {{ font-size: 11px; color: var(--muted); font-family: var(--mono); margin-bottom: 10px; }}
  .table {{ border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  .table-head {{
    display: grid; grid-template-columns: 96px 100px 1fr 160px;
    padding: 8px 14px; background: var(--bg2);
    border-bottom: 1px solid var(--border); gap: 10px;
  }}
  .table-head span {{
    font-size: 10px; color: var(--muted); font-weight: 700;
    text-transform: uppercase; letter-spacing: .1em; font-family: var(--mono);
  }}
  .row {{
    display: grid; grid-template-columns: 96px 100px 1fr 160px;
    padding: 11px 14px; border-bottom: 1px solid #0e1016;
    gap: 10px; cursor: pointer; align-items: center;
    border-left: 3px solid transparent; transition: background .1s;
  }}
  .row:hover {{ background: var(--bg3); }}
  .row.selected {{ border-left-color: var(--crit); background: var(--bg3); }}
  .row-title {{ font-size: 13px; font-weight: 500; color: #dde; line-height: 1.3; }}
  .row-cat   {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .row-res   {{ font-family: var(--mono); font-size: 11px; color: var(--muted);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .empty {{ padding: 40px; text-align: center; color: var(--muted); font-size: 13px; }}
  .sev-badge, .type-badge {{
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: 4px; font-size: 10px;
    font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
    font-family: var(--mono); white-space: nowrap;
  }}
  .dot {{ width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }}
  .sev-Critical {{ background: var(--crit-bg); border: 1px solid var(--crit); color: var(--crit-t); }}
  .sev-High     {{ background: var(--high-bg); border: 1px solid var(--high); color: var(--high-t); }}
  .sev-Medium   {{ background: var(--med-bg);  border: 1px solid var(--med);  color: var(--med-t);  }}
  .sev-Low      {{ background: var(--low-bg);  border: 1px solid var(--low);  color: var(--low-t);  }}
  .sev-Info     {{ background: var(--info-bg); border: 1px solid var(--info); color: var(--info-t); }}
  .type-check      {{ background: #7c6af722; border: 1px solid #7c6af744; color: #9c8af9; }}
  .type-dependency {{ background: #22c9a022; border: 1px solid #22c9a044; color: #44ddb0; }}
  .type-secret     {{ background: #f76a6a22; border: 1px solid #f76a6a44; color: #f98a8a; }}
  .close-btn {{
    background: none; border: 1px solid var(--border2); color: var(--muted);
    border-radius: 4px; padding: 3px 10px; cursor: pointer;
    font-size: 11px; font-family: var(--mono); margin-bottom: 18px;
  }}
  .close-btn:hover {{ border-color: var(--med); color: var(--med-t); }}
  .detail-badges {{ display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }}
  .detail-title  {{ font-size: 14px; font-weight: 700; color: #eee; margin-bottom: 4px; line-height: 1.4; }}
  .detail-id     {{ font-family: var(--mono); font-size: 11px; color: var(--muted); margin-bottom: 18px; }}
  .section {{ margin-bottom: 16px; }}
  .section-label {{
    font-size: 10px; color: var(--muted); font-weight: 700;
    text-transform: uppercase; letter-spacing: .1em;
    margin-bottom: 6px; font-family: var(--mono);
  }}
  .section p  {{ font-size: 13px; color: #aab; line-height: 1.6; }}
  .code-block {{
    background: #080a10; border-radius: 6px; padding: 10px 12px;
    font-family: var(--mono); font-size: 12px; word-break: break-all;
  }}
  .risk-block {{
    background: #1e1208; border: 1px solid #ff8c0020; border-radius: 6px;
    padding: 10px 12px; font-size: 13px; color: #cc8844; line-height: 1.6;
  }}
  .fix-block {{
    background: #0a180e; border: 1px solid #44cc7720; border-radius: 6px;
    padding: 10px 12px; font-size: 13px; color: #66cc88; line-height: 1.6;
  }}
  .warn-block {{
    background: #1e0a0a; border: 1px solid #ff444420; border-radius: 6px;
    padding: 10px 12px; font-size: 12px; color: #ff8888; line-height: 1.5;
  }}
</style>
</head>
<body>
<div class="header">
  <div class="logo">
    <div class="logo-icon">🔒</div>
    <div>
      <div class="logo-name">gitsec</div>
      <div class="logo-sub">security posture report</div>
    </div>
  </div>
  <div class="meta" id="meta-info">—</div>
</div>
<div class="main">
  <div class="list-pane">
    <div class="cards" id="cards"></div>
    <div class="filters">
      <input id="search" placeholder="search findings..." oninput="applyFilters()"/>
      <div class="filter-group">
        <span class="filter-label">Severity</span>
        <button class="filter-btn active" data-sev="All"      onclick="setSev(this)">All</button>
        <button class="filter-btn"        data-sev="Critical" onclick="setSev(this)">Critical</button>
        <button class="filter-btn"        data-sev="High"     onclick="setSev(this)">High</button>
        <button class="filter-btn"        data-sev="Medium"   onclick="setSev(this)">Medium</button>
        <button class="filter-btn"        data-sev="Low"      onclick="setSev(this)">Low</button>
      </div>
      <div class="filter-group">
        <span class="filter-label">Type</span>
        <button class="filter-btn active" data-type="All"        onclick="setType(this)">All</button>
        <button class="filter-btn"        data-type="check"      onclick="setType(this)">Check</button>
        <button class="filter-btn"        data-type="dependency" onclick="setType(this)">Dependency</button>
        <button class="filter-btn"        data-type="secret"     onclick="setType(this)">Secret</button>
      </div>
    </div>
    <div class="result-count" id="result-count"></div>
    <div class="table">
      <div class="table-head">
        <span>Severity</span><span>Type</span><span>Finding</span><span>Resource</span>
      </div>
      <div id="rows"></div>
    </div>
  </div>
  <div class="detail-pane" id="detail">
    <button class="close-btn" onclick="closeDetail()">← close</button>
    <div id="detail-content"></div>
  </div>
</div>
<script>
const REPORT = {data_json};
let activeSev = 'All', activeType = 'All', selectedIdx = null;
 
document.addEventListener('DOMContentLoaded', () => {{
  renderCards();
  applyFilters();
  document.getElementById('meta-info').textContent =
    REPORT.findings.length + ' findings · ' + new Date().toLocaleDateString('en-GB');
}});
 
function renderCards() {{
  const s = REPORT.summary;
  const sevColors = {{Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)'}};
  const typeColors = {{check:'#9c8af9',dependency:'#44ddb0',secret:'#f98a8a'}};
  const typeLabels = {{check:'Checks',dependency:'Dep CVEs',secret:'Secrets'}};
  let html = `<div class="card" style="border-top:3px solid #7c6af7">
    <div class="card-num" style="color:#7c6af7">${{s.total}}</div>
    <div class="card-label">Total</div></div>`;
  for (const [sev, color] of Object.entries(sevColors)) {{
    html += `<div class="card" style="border-top:3px solid ${{color}}">
      <div class="card-num" style="color:${{color}}">${{s.by_severity[sev]||0}}</div>
      <div class="card-label">${{sev}}</div></div>`;
  }}
  for (const [type, label] of Object.entries(typeLabels)) {{
    html += `<div class="card" style="border-top:3px solid ${{typeColors[type]}}">
      <div class="card-num" style="color:${{typeColors[type]}}">${{s.by_type[type]||0}}</div>
      <div class="card-label">${{label}}</div></div>`;
  }}
  document.getElementById('cards').innerHTML = html;
}}
 
function setSev(btn) {{
  activeSev = btn.dataset.sev;
  document.querySelectorAll('[data-sev]').forEach(b => b.className = 'filter-btn');
  btn.classList.add(activeSev === 'All' ? 'active' : 'active-' + activeSev.toLowerCase().slice(0,4));
  applyFilters();
}}
 
function setType(btn) {{
  activeType = btn.dataset.type;
  document.querySelectorAll('[data-type]').forEach(b => b.className = 'filter-btn');
  btn.classList.add('active');
  applyFilters();
}}
 
function applyFilters() {{
  const q = document.getElementById('search').value.toLowerCase();
  const filtered = REPORT.findings.filter(f => {{
    if (activeSev  !== 'All' && f.severity !== activeSev)  return false;
    if (activeType !== 'All' && f.type     !== activeType) return false;
    if (q && !((f.title||'').toLowerCase().includes(q) ||
               (f.resource||'').toLowerCase().includes(q) ||
               (f.category||'').toLowerCase().includes(q))) return false;
    return true;
  }});
  document.getElementById('result-count').textContent =
    'showing ' + filtered.length + ' of ' + REPORT.findings.length + ' findings';
  renderRows(filtered);
}}
 
function renderRows(findings) {{
  if (!findings.length) {{
    document.getElementById('rows').innerHTML = '<div class="empty">no findings match the current filters</div>';
    return;
  }}
  const dots = {{Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'}};
  document.getElementById('rows').innerHTML = findings.map(f => {{
    const origIdx = REPORT.findings.indexOf(f);
    const sel = selectedIdx === origIdx ? 'selected' : '';
    const dot = `<span class="dot" style="background:${{dots[f.severity]||dots.Info}}"></span>`;
    return `<div class="row ${{sel}}" onclick="openDetail(${{origIdx}})">
      <div><span class="sev-badge sev-${{f.severity}}">${{dot}}${{f.severity}}</span></div>
      <div><span class="type-badge type-${{f.type}}">${{f.type}}</span></div>
      <div>
        <div class="row-title">${{esc(f.title)}}</div>
        ${{f.category ? `<div class="row-cat">${{esc(f.category)}}</div>` : ''}}
      </div>
      <div class="row-res">${{esc(f.resource)}}</div>
    </div>`;
  }}).join('');
}}
 
function openDetail(idx) {{
  selectedIdx = idx;
  const f = REPORT.findings[idx];
  const id = f.check_id || f.advisory_id || f.secret_type || '';
  const dots = {{Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'}};
  const dot = `<span class="dot" style="background:${{dots[f.severity]||dots.Info}}"></span>`;
  let html = `
    <div class="detail-badges">
      <span class="sev-badge sev-${{f.severity}}">${{dot}}${{f.severity}}</span>
      <span class="type-badge type-${{f.type}}">${{f.type}}</span>
    </div>
    <div class="detail-title">${{esc(f.title)}}</div>
    <div class="detail-id">${{esc(id)}}</div>
    <div class="section">
      <div class="section-label">Resource</div>
      <div class="code-block" style="color:var(--med-t)">${{esc(f.resource)}}</div>
    </div>
    <div class="section">
      <div class="section-label">Evidence</div>
      <div class="code-block" style="color:var(--crit-t)">${{esc(f.evidence)}}</div>
    </div>`;
  if (f.description) html += `<div class="section"><div class="section-label">What this means</div><p>${{esc(f.description)}}</p></div>`;
  if (f.risk)        html += `<div class="section"><div class="section-label">Risk</div><div class="risk-block">${{esc(f.risk)}}</div></div>`;
  if (f.remediation) html += `<div class="section"><div class="section-label">How to fix it</div><div class="fix-block">${{esc(f.remediation)}}</div></div>`;
  if (f.type === 'dependency') html += `
    <div class="section"><div class="section-label">Package</div>
    <div class="code-block">${{esc(f.package)}}@${{esc(f.version)}} (${{esc(f.ecosystem)}})</div></div>
    <div class="section"><div class="section-label">CVSS Score</div>
    <div class="code-block" style="color:var(--high-t)">${{esc(String(f.cvss_score))}}</div></div>`;
  if (f.type === 'secret') html += `
    <div class="section"><div class="section-label">File</div>
    <div class="code-block">${{esc(f.file_path)}}${{f.line_number ? ':'+f.line_number : ''}}</div></div>
    <div class="warn-block">⚠ Rotate this credential immediately.</div>`;
  if (f.reference_url) html += `
    <div class="section" style="margin-top:16px"><div class="section-label">Reference</div>
    <a href="${{esc(f.reference_url)}}" target="_blank">${{esc(f.reference_url)}}</a></div>`;
  document.getElementById('detail-content').innerHTML = html;
  document.getElementById('detail').classList.add('open');
  applyFilters();
}}
 
function closeDetail() {{
  selectedIdx = null;
  document.getElementById('detail').classList.remove('open');
  applyFilters();
}}
 
function esc(s) {{
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
</script>
</body>
</html>"""
