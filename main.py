from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
from datetime import datetime
import uuid
import random
import html
CLOUD_DEMO_URL = "https://preclear-demo.onrender.com/"

app = FastAPI(title="PreClear Investor Demo")

REPORT_STORE: dict[str, dict] = {}
REPORT_ORDER: list[str] = []
MAX_REPORTS = 20

def store_report(report: dict) -> str:
    report_id = report["report_id"]
    REPORT_STORE[report_id] = report
    REPORT_ORDER.insert(0, report_id)  # newest first

    # Trim old
    while len(REPORT_ORDER) > MAX_REPORTS:
        old_id = REPORT_ORDER.pop()
        REPORT_STORE.pop(old_id, None)

    return report_id

app.mount("/static", StaticFiles(directory="static"), name="static")

def behavioral_analysis(file_content: bytes):
    score = random.randint(1, 100)
    behavior_flags = []
    if score > 35:
        behavior_flags.append("Observed suspicious script execution pattern")
    if score > 55:
        behavior_flags.append("Outbound network callback behavior detected")
    if score > 75:
        behavior_flags.append("Privilege escalation / credential access behavior")
    return score, behavior_flags


def deception_check():
    return random.choice([True, False, False, False])


def classify_verdict(final_risk_score: int, deception_triggered: bool):
    if deception_triggered:
        return "BLOCKED", "Deception trigger indicates confirmed malicious intent."
    if final_risk_score >= 80:
        return "BLOCKED", "High-confidence malicious behavioral indicators."
    if final_risk_score >= 55:
        return "QUARANTINED", "Suspicious indicators; requires further validation."
    return "CLEARED", "No significant malicious behavior detected."


def risk_color(score: int):
    if score >= 80:
        return "#B00020"
    if score >= 55:
        return "#B26A00"
    return "#0B6E4F"


def generate_soc_noise():
    tool_sources = ["EDR", "SIEM", "Email Gateway", "CASB", "IAM", "Firewall", "Proxy", "DLP"]
    alert_titles = [
        "Suspicious PowerShell activity",
        "Unusual login location",
        "New device registered",
        "Multiple failed login attempts",
        "Possible phishing link clicked",
        "Outbound connection to unknown domain",
        "Rare process execution",
        "OAuth consent granted to new app",
        "Anomalous file download volume",
        "New admin permission assigned",
        "DNS query to newly registered domain",
        "Credential stuffing pattern suspected",
    ]
    severities = ["Low", "Medium", "Medium", "High", "Low", "Medium"]
    alerts = []
    count = random.randint(18, 35)
    for _ in range(count):
        alerts.append({
            "tool": random.choice(tool_sources),
            "sev": random.choice(severities),
            "title": random.choice(alert_titles)
        })
    return alerts


BASE_CSS = """
<style>
:root {
  --ink: #0b1220;
  --muted: #5b667a;
  --bg: #f6f8fc;
  --card: #ffffff;
  --line: #e5e9f2;
  --blue: #0a3278;
  --accent: #1e78ff;
  --shadow: 0 10px 30px rgba(8, 22, 54, 0.08);
  --radius: 18px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
}

* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: var(--sans);
  color: var(--ink);
  background: radial-gradient(900px 600px at 15% 0%, rgba(30,120,255,0.12), transparent 60%),
              radial-gradient(900px 600px at 85% 10%, rgba(10,50,120,0.10), transparent 55%),
              var(--bg);
}

.container { max-width: 980px; margin: 44px auto; padding: 0 18px; }
.header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }

.brand { display: flex; align-items: center; gap: 12px; }
.logo { width: 42px; height: 42px; border-radius: 14px; background: linear-gradient(135deg, var(--accent), var(--blue)); box-shadow: var(--shadow); }
.brand h1 { margin: 0; font-size: 20px; letter-spacing: 0.2px; }
.brand p { margin: 2px 0 0 0; color: var(--muted); font-size: 13px; }

.pill { font-size: 12px; color: var(--muted); border: 1px solid var(--line); background: rgba(255,255,255,0.7); padding: 8px 12px; border-radius: 999px; }

.grid { display: grid; grid-template-columns: 1.2fr 0.8fr; gap: 18px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); padding: 18px; }
.card h2 { margin: 0 0 10px 0; font-size: 16px; }
.subtle { color: var(--muted); font-size: 13px; line-height: 1.45; }

.upload { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }
input[type="file"] { padding: 12px; border: 1px dashed var(--line); border-radius: 14px; background: #fbfcff; }

button { border: 0; border-radius: 14px; padding: 12px 14px; font-weight: 600; cursor: pointer;
  background: linear-gradient(135deg, var(--accent), var(--blue)); color: white;
  box-shadow: 0 10px 22px rgba(30,120,255,0.22);
}
button:hover { filter: brightness(1.02); }

.btn-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  border-radius: 14px;
  padding: 12px 14px;
  font-weight: 600;
  cursor: pointer;
  background: linear-gradient(135deg, var(--accent), var(--blue));
  color: white !important;
  box-shadow: 0 10px 22px rgba(30,120,255,0.22);
  border: 0;
}
.btn-link:hover { filter: brightness(1.02); }

.btn-link.secondary {
  background: #e9edf7;
  color: var(--ink) !important;
  box-shadow: none;
  border: 1px solid var(--line);
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 10px;
  margin: 12px 0 4px 0;
}

.metric {
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 12px;
  background: #fbfcff;
}

.metric .k {
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 6px;
}

.metric .v {
  font-family: var(--mono);
  font-size: 18px;
  font-weight: 700;
  letter-spacing: 0.2px;
}

.metric .s {
  margin-top: 6px;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.35;
}

@media (max-width: 860px) {
  .metrics { grid-template-columns: repeat(2, 1fr); }
}

.kv { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
.kv .item { border: 1px solid var(--line); border-radius: 14px; padding: 12px; background: #fbfcff; }
.kv .label { font-size: 11px; color: var(--muted); margin-bottom: 6px; }
.kv .value { font-family: var(--mono); font-size: 12px; color: var(--ink); word-break: break-word; }

.verdict { display: inline-flex; align-items: center; gap: 8px; border-radius: 999px; padding: 8px 12px; font-weight: 700; font-size: 12px; border: 1px solid var(--line); }
.badge-dot { width: 9px; height: 9px; border-radius: 99px; background: #999; }

.progress { margin-top: 14px; border: 1px solid var(--line); border-radius: 14px; padding: 10px; background: #fbfcff; }
.bar { height: 12px; border-radius: 999px; background: #e9edf7; overflow: hidden; }
.bar > div { height: 100%; width: 0%; }

.timeline { margin: 0; padding-left: 18px; color: var(--ink); }
.timeline li { margin: 8px 0; }
hr { border: 0; border-top: 1px solid var(--line); margin: 14px 0; }

.footer { margin-top: 18px; color: var(--muted); font-size: 12px; text-align: center; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.split { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 14px; }
.panel { border: 1px solid var(--line); border-radius: 16px; padding: 12px; background: #fbfcff; }
.panel h3 { margin: 0 0 8px 0; font-size: 13px; letter-spacing: 0.2px; }

.table { width: 100%; border-collapse: collapse; font-size: 12px; }
.table th, .table td { text-align: left; padding: 8px 6px; border-bottom: 1px solid var(--line); vertical-align: top; }

.mono { font-family: var(--mono); }
.tag { display: inline-flex; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--line);
  font-size: 11px; color: var(--muted); background: rgba(255,255,255,0.75);
}

.logo-img {
  width: 52px;
  height: auto;
  border-radius: 12px;
}

/* Attack Replay */
.replay-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 12px 0 14px 0;
}
.replay {
  border: 1px solid var(--line);
  border-radius: 16px;
  padding: 14px;
  background: #fbfcff;
}
.replay-step {
  display: grid;
  grid-template-columns: 34px 1fr;
  gap: 10px;
  padding: 10px 6px;
  opacity: 0.35;
  transform: translateY(4px);
  transition: opacity 350ms ease, transform 350ms ease;
}
.replay-step.active {
  opacity: 1;
  transform: translateY(0);
}
.replay-left {
  position: relative;
  display: flex;
  justify-content: center;
}
.replay-dot {
  width: 12px;
  height: 12px;
  border-radius: 999px;
  border: 2px solid var(--accent);
  background: white;
  box-shadow: 0 8px 18px rgba(30,120,255,0.12);
  margin-top: 2px;
}
.replay-line {
  position: absolute;
  top: 18px;
  bottom: -8px;
  width: 2px;
  background: var(--line);
}
.replay-title {
  font-weight: 700;
  font-size: 13px;
  margin-bottom: 4px;
}
.replay-desc {
  color: var(--muted);
  font-size: 13px;
  line-height: 1.45;
}

@media (max-width: 860px) { .grid { grid-template-columns: 1fr; } .split { grid-template-columns: 1fr; } }
</style>
"""

def page_shell(content: str, right_pill: str):
    return f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PreClear Demo</title>
  {BASE_CSS}
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">
        <img src="/static/Blue.png" class="logo-img">
        <div>
          <h1>PreClear</h1>
          <p>Pre-ingress threat interception • demo environment</p>
        </div>
      </div>
      <div class="pill">{html.escape(right_pill)}</div>
    </div>
    {content}
    <div class="footer">PreClear demo • This prototype simulates detection logic for presentation purposes.</div>
  </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    content = """
<div class="grid">
  <div class="card">
    <h2>Upload Artifact for Pre-Ingress Analysis</h2>
    <p class="subtle">
      Upload any file to generate an analysis report (behavioral signals + deception trigger + risk verdict).
    </p>
    <div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:10px;">
      <a class="btn-link secondary" href="https://preclear-demo.onrender.com/" target="_blank" rel="noopener noreferrer">
        ☁ Open Cloud Demo
      </a>
</div>
    <div class="metrics">
  <div class="metric">
    <div class="k">Time to Decision</div>
    <div class="v">~3s</div>
    <div class="s">Automated correlation + verdict</div>
  </div>
  <div class="metric">
    <div class="k">Alert Reduction</div>
    <div class="v">90%+</div>
    <div class="s">Fewer, higher-confidence signals</div>
  </div>
  <div class="metric">
    <div class="k">Confidence Signal</div>
    <div class="v">Deception</div>
    <div class="s">Deterministic tripwires reduce false positives</div>
  </div>
  <div class="metric">
    <div class="k">Outcome</div>
    <div class="v">Pre-Ingress</div>
    <div class="s">Stops threats before compromise</div>
  </div>
</div>
    <hr/>
    <form action="/demo" method="get">
     <button type="submit">🎬 Run Investor Demo Mode</button>
    </form>
    <p class="subtle" style="margin-top:8px;">
     Fully automated replay + detection sequence.
    </p>
    <form class="upload" action="/analyze" enctype="multipart/form-data" method="post">
      <input name="file" type="file" required />
      <button type="submit">Analyze & Generate Report</button>
    </form>
  </div>

  <div class="card">
    <h2>What This Demonstrates</h2>
    <ul class="timeline">
      <li>Early-stage detection posture</li>
      <li>Behavior-based scoring (sandbox)</li>
      <li>High-confidence signal (deception)</li>
      <li>Traditional SOC noise vs PreClear clarity</li>
    </ul>
    <hr/>
    <p class="subtle">API docs: <a href="/docs">/docs</a></p>
  </div>
</div>
"""
    return page_shell(content, "Upload → Report")

def render_report_html(report: dict) -> HTMLResponse:
    filename = report["filename"]
    verdict = report["verdict"]
    rationale = report["rationale"]
    final_risk = report["final_risk"]
    deception_triggered = report["deception_triggered"]
    behavior_score = report["behavior_score"]
    flags = report["flags"]
    steps = report["steps"]
    report_id = report["report_id"]
    created_at = report["created_at"]

    color = risk_color(final_risk)

    # SOC noise table
    soc_alerts = report["soc_alerts"]
    rows = []
    for a in soc_alerts[:12]:
        rows.append(
            f"<tr><td class='mono'>{html.escape(a['tool'])}</td>"
            f"<td><span class='tag'>{html.escape(a['sev'])}</span></td>"
            f"<td>{html.escape(a['title'])}</td></tr>"
        )
    soc_table_html = "".join(rows)
    extra_count = max(0, len(soc_alerts) - 12)

    flags_html = "".join(f"<li>{html.escape(f)}</li>" for f in flags) if flags else "<li>No significant behavioral flags.</li>"

    content = f"""
<div class="grid">
  <div class="card">
    <h2>Analysis Report</h2>
    <p class="subtle">
      Artifact: <span class="mono">{html.escape(filename)}</span><br/>
      Report ID: <span class="mono">{html.escape(report_id)}</span><br/>
      Generated: <span class="mono">{html.escape(created_at)}</span>
    </p>

    <div class="verdict">
      <span class="badge-dot" style="background:{color};"></span>
      Verdict: <span style="color:{color};">{html.escape(verdict)}</span>
    </div>
    <p class="subtle" style="margin-top:10px;">{html.escape(rationale)}</p>

    <div class="progress">
      <div class="subtle" style="margin-bottom:8px;">
        Final Risk Score: <span class="mono">{final_risk}/100</span>
        {"• Deception Triggered" if deception_triggered else ""}
      </div>
      <div class="bar"><div style="width:{final_risk}%; background:{color};"></div></div>
    </div>

    <div class="kv">
      <div class="item">
        <div class="label">Behavior Score</div>
        <div class="value">{behavior_score}/100</div>
      </div>
      <div class="item">
        <div class="label">Deception Triggered</div>
        <div class="value">{'YES' if deception_triggered else 'NO'}</div>
      </div>
    </div>

    <hr/>
    <h2>Behavioral Indicators</h2>
    <ul class="timeline">{flags_html}</ul>

    <hr/>
    <h2>Threat Interception Timeline</h2>
    <ol class="timeline">
      {''.join(f'<li>{html.escape(s)}</li>' for s in steps)}
    </ol>

    <hr/>
    <h2>Why PreClear Matters (Split Screen)</h2>
    <p class="subtle">
      Traditional tools generate many ambiguous alerts; PreClear produces fewer, higher-confidence signals and an immediate action.
    </p>

    <div class="split">
      <div class="panel">
        <h3>Traditional SOC View (Noise)</h3>
        <table class="table">
          <thead><tr><th>Source</th><th>Sev</th><th>Alert</th></tr></thead>
          <tbody>{soc_table_html}</tbody>
        </table>
        <p class="subtle" style="margin-bottom:0;">+ {extra_count} more alerts requiring triage…</p>
      </div>

      <div class="panel">
        <h3>PreClear View (Clarity)</h3>
        <div class="kv" style="margin-top:10px;">
          <div class="item">
            <div class="label">Verdict</div>
            <div class="value">{html.escape(verdict)}</div>
          </div>
          <div class="item">
            <div class="label">Action</div>
            <div class="value">{'Block & contain' if verdict == 'BLOCKED' else 'Quarantine for review' if verdict == 'QUARANTINED' else 'Allow'}</div>
          </div>
          <div class="item">
            <div class="label">Confidence Signal</div>
            <div class="value">{'Deception trigger (deterministic)' if deception_triggered else 'Behavioral correlation (scored)'}</div>
          </div>
          <div class="item">
            <div class="label">Time to Decision</div>
            <div class="value">Seconds (automated)</div>
          </div>
        </div>
      </div>
    </div>

    <hr/>
    <p class="subtle">
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <a class="btn-link secondary" href="/">Back to home</a>
        <a class="btn-link secondary" href="/history">View history</a>
        <a class="btn-link" href="/simulate">▶ Simulate Attack (Replay)</a>
    </div>

    </p>
  </div>

  <div class="card">
    <h2>Investor Narrative</h2>
    <p class="subtle">
      PreClear stops threats <b>before compromise</b> by combining early-stage signals:
      behavioral analysis, high-confidence deception triggers, and automated response.
    </p>
    <ul class="timeline">
      <li><b>Earlier:</b> before endpoint execution and lateral movement</li>
      <li><b>Cleaner:</b> deception reduces false positives</li>
      <li><b>Faster:</b> automation beats human triage</li>
    </ul>
    <hr/>
    <p class="subtle"><a href="/simulate">▶ Run Attack Replay</a></p>
  </div>
</div>
"""
    return HTMLResponse(page_shell(content, "Report Generated"))

def render_report_html(report: dict) -> HTMLResponse:
    filename = report["filename"]
    verdict = report["verdict"]
    rationale = report["rationale"]
    final_risk = report["final_risk"]
    deception_triggered = report["deception_triggered"]
    behavior_score = report["behavior_score"]
    flags = report["flags"]
    steps = report["steps"]
    report_id = report["report_id"]
    created_at = report["created_at"]

    color = risk_color(final_risk)

    soc_alerts = report["soc_alerts"]
    rows = []
    for a in soc_alerts[:12]:
        rows.append(
            f"<tr><td class='mono'>{html.escape(a['tool'])}</td>"
            f"<td><span class='tag'>{html.escape(a['sev'])}</span></td>"
            f"<td>{html.escape(a['title'])}</td></tr>"
        )
    soc_table_html = "".join(rows)
    extra_count = max(0, len(soc_alerts) - 12)

    flags_html = "".join(f"<li>{html.escape(f)}</li>" for f in flags) if flags else "<li>No significant behavioral flags.</li>"

    content = f"""
<div class="grid">
  <div class="card">
    <h2>Analysis Report</h2>
    <p class="subtle">
      Artifact: <span class="mono">{html.escape(filename)}</span><br/>
      Report ID: <span class="mono">{html.escape(report_id)}</span><br/>
      Generated: <span class="mono">{html.escape(created_at)}</span>
    </p>

    <div class="verdict">
      <span class="badge-dot" style="background:{color};"></span>
      Verdict: <span style="color:{color};">{html.escape(verdict)}</span>
    </div>
    <p class="subtle" style="margin-top:10px;">{html.escape(rationale)}</p>

    <div class="progress">
      <div class="subtle" style="margin-bottom:8px;">
        Final Risk Score: <span class="mono">{final_risk}/100</span>
        {"• Deception Triggered" if deception_triggered else ""}
      </div>
      <div class="bar"><div style="width:{final_risk}%; background:{color};"></div></div>
    </div>

    <div class="kv">
      <div class="item">
        <div class="label">Behavior Score</div>
        <div class="value">{behavior_score}/100</div>
      </div>
      <div class="item">
        <div class="label">Deception Triggered</div>
        <div class="value">{'YES' if deception_triggered else 'NO'}</div>
      </div>
    </div>

    <hr/>
    <h2>Behavioral Indicators</h2>
    <ul class="timeline">{flags_html}</ul>

    <hr/>
    <h2>Threat Interception Timeline</h2>
    <ol class="timeline">
      {''.join(f'<li>{html.escape(s)}</li>' for s in steps)}
    </ol>

    <hr/>
    <h2>Why PreClear Matters (Split Screen)</h2>
    <p class="subtle">
      Traditional tools generate many ambiguous alerts; PreClear produces fewer, higher-confidence signals and an immediate action.
    </p>

    <div class="split">
      <div class="panel">
        <h3>Traditional SOC View (Noise)</h3>
        <table class="table">
          <thead><tr><th>Source</th><th>Sev</th><th>Alert</th></tr></thead>
          <tbody>{soc_table_html}</tbody>
        </table>
        <p class="subtle" style="margin-bottom:0;">+ {extra_count} more alerts requiring triage…</p>
      </div>

      <div class="panel">
        <h3>PreClear View (Clarity)</h3>
        <div class="kv" style="margin-top:10px;">
          <div class="item">
            <div class="label">Verdict</div>
            <div class="value">{html.escape(verdict)}</div>
          </div>
          <div class="item">
            <div class="label">Action</div>
            <div class="value">{'Block & contain' if verdict == 'BLOCKED' else 'Quarantine for review' if verdict == 'QUARANTINED' else 'Allow'}</div>
          </div>
          <div class="item">
            <div class="label">Confidence Signal</div>
            <div class="value">{'Deception trigger (deterministic)' if deception_triggered else 'Behavioral correlation (scored)'}</div>
          </div>
          <div class="item">
            <div class="label">Time to Decision</div>
            <div class="value">Seconds (automated)</div>
          </div>
        </div>
      </div>
    </div>

    <hr/>
    <p class="subtle">
      <div style="display:flex; gap:10px; flex-wrap:wrap;">
        <a class="btn-link secondary" href="/">Back to home</a>
        <a class="btn-link secondary" href="/history">View history</a>
        <a class="btn-link" href="/simulate">▶ Simulate Attack (Replay)</a>
        </div>
    </p>
  </div>

  <div class="card">
    <h2>Investor Narrative</h2>
    <p class="subtle">
      PreClear stops threats <b>before compromise</b> by combining early-stage signals:
      behavioral analysis, high-confidence deception triggers, and automated response.
    </p>
    <ul class="timeline">
      <li><b>Earlier:</b> before endpoint execution and lateral movement</li>
      <li><b>Cleaner:</b> deception reduces false positives</li>
      <li><b>Faster:</b> automation beats human triage</li>
    </ul>
    <hr/>
    <p class="subtle"><a class="btn-link secondary" href="/history">View History</a></p>
  </div>
</div>
"""
    return HTMLResponse(page_shell(content, "Report Generated"))

@app.post("/analyze", response_class=HTMLResponse)
async def analyze(file: UploadFile = File(...)):
    content_bytes = await file.read()
    filename = file.filename or "uploaded_file"

    behavior_score, flags = behavioral_analysis(content_bytes)
    deception_triggered = deception_check()
    final_risk = min(100, behavior_score + (30 if deception_triggered else 0))

    verdict, rationale = classify_verdict(final_risk, deception_triggered)

    steps = [
        "Ingress captured and artifact extracted",
        "Behavioral sandbox executed (simulated)",
        "Behavioral indicators scored",
    ]
    if deception_triggered:
        steps.append("Deception asset accessed → confirmed malicious intent")
    steps.append("Risk engine produced verdict")
    steps.append(
        "Automated action: "
        + ("Block & contain" if verdict == "BLOCKED" else "Quarantine for review" if verdict == "QUARANTINED" else "Allow")
    )

    soc_alerts = generate_soc_noise()

    report_id = uuid.uuid4().hex[:10]
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "report_id": report_id,
        "created_at": created_at,
        "filename": filename,
        "behavior_score": behavior_score,
        "deception_triggered": deception_triggered,
        "final_risk": final_risk,
        "verdict": verdict,
        "rationale": rationale,
        "flags": flags,
        "steps": steps,
        "soc_alerts": soc_alerts,
    }

    store_report(report)
    return render_report_html(report)

@app.get("/simulate", response_class=HTMLResponse)
async def simulate():
    # All simulated narrative steps (no real payloads)
    steps = [
        ("Reconnaissance", "Attacker enumerates exposed services and targets identities."),
        ("Credential Testing", "Password spraying / token probing begins (low-and-slow)."),
        ("Payload Staging", "Malicious content is prepared for delivery (file/link)."),
        ("PreClear Behavioral Sandbox", "Artifact detonated in isolation; behaviors recorded."),
        ("Deception Tripwire", "Decoy identity / token accessed → high-confidence intent."),
        ("Risk Engine Correlation", "Signals fused → confidence raised → verdict produced."),
        ("Automated Action", "Block/quarantine + notify SIEM/SOC + optional token revoke."),
        ("Outcome", "Threat stopped before reaching internal systems."),
    ]

    steps_html = "".join(
        f"""
        <div class="replay-step" data-step>
          <div class="replay-left">
            <div class="replay-dot"></div>
            <div class="replay-line"></div>
          </div>
          <div class="replay-body">
            <div class="replay-title">{html.escape(title)}</div>
            <div class="replay-desc">{html.escape(desc)}</div>
          </div>
        </div>
        """
        for title, desc in steps
    )

    content = f"""
<div class="grid">
  <div class="card">
    <h2>Attack Replay (Simulated)</h2>
    <p class="subtle">
      This replay illustrates how PreClear intercepts attacker intent <b>before compromise</b>.
      It is a narrative simulation designed for investor and design-partner demos.
    </p>

    <div class="replay-controls">
      <button type="button" onclick="startReplay()">▶ Start Replay</button>
      <button type="button" onclick="resetReplay()" style="background: #e9edf7; color: #0b1220; box-shadow: none; border: 1px solid #e5e9f2;">
        Reset
      </button>
      <span class="pill" id="replayStatus">Ready</span>
    </div>

    <div class="replay">
      {steps_html}
    </div>

    <hr/>
    <div style="margin-top:14px;">
        <a class="btn-link secondary" href="/">Back to Upload</a>
    </div>

  </div>

  <div class="card">
    <h2>Demo Talking Points</h2>
    <ul class="timeline">
      <li><b>Timing shift:</b> detection starts before endpoint execution.</li>
      <li><b>Signal quality:</b> deception triggers reduce false positives.</li>
      <li><b>Automation:</b> decision and action occur in seconds.</li>
      <li><b>SOC impact:</b> fewer alerts, higher confidence, faster response.</li>
    </ul>
    <hr/>
    <p class="subtle">
      Tip: Run this replay first, then upload a file to generate a report.
    </p>
  </div>
</div>

<script>
let replayTimer = null;

function startReplay() {{
  resetReplay(false);
  const steps = Array.from(document.querySelectorAll("[data-step]"));
  const status = document.getElementById("replayStatus");
  let i = 0;
  status.textContent = "Running…";

  replayTimer = setInterval(() => {{
    if (i >= steps.length) {{
      clearInterval(replayTimer);
      replayTimer = null;
      status.textContent = "Complete";
      return;
    }}
    steps[i].classList.add("active");
    i += 1;
  }}, 900);
}}

function resetReplay(setReady=true) {{
  if (replayTimer) {{
    clearInterval(replayTimer);
    replayTimer = null;
  }}
  document.querySelectorAll("[data-step]").forEach(el => el.classList.remove("active"));
  if (setReady) {{
    document.getElementById("replayStatus").textContent = "Ready";
  }}
}}
</script>
"""
    return page_shell(content, "Attack Replay")

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def view_report(report_id: str):
    report = REPORT_STORE.get(report_id)
    if not report:
        return page_shell(
            f"""
            <div class="card">
              <h2>Report not found</h2>
              <p class="subtle">This report may have expired (history keeps the last {MAX_REPORTS}).</p>
              <p class="subtle"><a href="/">Back to home</a></p>
            </div>
            """,
            "Report Missing"
        )

    # Re-render using the same report template you use after analysis
    return render_report_html(report)

@app.get("/history", response_class=HTMLResponse)
async def history():
    items = []
    for rid in REPORT_ORDER:
        r = REPORT_STORE.get(rid)
        if not r:
            continue
        items.append(
            f"""
            <tr>
              <td class="mono">{html.escape(r["created_at"])}</td>
              <td class="mono">{html.escape(r["filename"])}</td>
              <td><span class="tag">{html.escape(r["verdict"])}</span></td>
              <td class="mono">{r["final_risk"]}/100</td>
              <td><a href="/report/{html.escape(rid)}">Open</a></td>
            </tr>
            """
        )

    table = "".join(items) if items else "<tr><td colspan='5' class='subtle'>No reports yet.</td></tr>"

    content = f"""
<div class="card">
  <h2>Recent Analyses (Last {MAX_REPORTS})</h2>
  <p class="subtle">Reports are stored in memory and reset when the server restarts.</p>
  <table class="table">
    <thead>
      <tr>
        <th>Time</th>
        <th>Artifact</th>
        <th>Verdict</th>
        <th>Risk</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {table}
    </tbody>
  </table>
  <hr/>
    <div style="margin-top:14px;">
        <a class="btn-link secondary" href="/">Back to Home</a>
    </div>
</div>
"""
    return HTMLResponse(page_shell(content, "History"))

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def view_report(report_id: str):
    report = REPORT_STORE.get(report_id)
    if not report:
        content = f"""
<div class="card">
  <h2>Report not found</h2>
  <p class="subtle">This report may have expired (history keeps the last {MAX_REPORTS}).</p>
  <p class="subtle"><a href="/history">Back to history</a></p>
</div>
"""
        return HTMLResponse(page_shell(content, "Not Found"))
    return render_report_html(report)

@app.get("/demo", response_class=HTMLResponse)
async def demo_mode():
    content = """
<div class="card">
  <h2>Investor Demo Mode</h2>
  <p class="subtle">
    Demonstrating full pre-ingress interception workflow...
  </p>

  <div id="demoStatus" class="pill">Initializing…</div>

  <div class="progress" style="margin-top:14px;">
    <div class="bar">
      <div id="demoBar" style="width:0%; background:var(--accent);"></div>
    </div>
  </div>

  <p class="subtle" style="margin-top:16px;">
    This will automatically run the attack replay and generate a report.
  </p>
</div>

<script>
let progress = 0;
const bar = document.getElementById("demoBar");
const status = document.getElementById("demoStatus");

const steps = [
  {p: 15, t: "Reconnaissance detected…"},
  {p: 30, t: "Behavioral sandbox executing…"},
  {p: 50, t: "Deception trigger activated…"},
  {p: 75, t: "Risk engine correlating signals…"},
  {p: 95, t: "Generating prevention verdict…"}
];

let i = 0;

function runDemo() {
  if (i >= steps.length) {
    status.textContent = "Complete. Loading report…";
    setTimeout(() => {
      window.location.href = "/demo-report";
    }, 1200);
    return;
  }

  status.textContent = steps[i].t;
  progress = steps[i].p;
  bar.style.width = progress + "%";
  i++;
  setTimeout(runDemo, 1000);
}

setTimeout(runDemo, 800);
</script>
"""
    return HTMLResponse(page_shell(content, "Demo Mode"))

@app.get("/demo-report", response_class=HTMLResponse)
async def demo_report():
    behavior_score = 82
    deception_triggered = True
    final_risk = 100
    verdict = "BLOCKED"
    rationale = "High-confidence deception signal confirms malicious intent."

    steps = [
        "Ingress captured and artifact extracted",
        "Behavioral sandbox executed (simulated)",
        "Deception asset accessed → confirmed malicious intent",
        "Risk engine produced verdict",
        "Automated action: Block & contain"
    ]

    soc_alerts = generate_soc_noise()

    report_id = uuid.uuid4().hex[:10]
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "report_id": report_id,
        "created_at": created_at,
        "filename": "simulated_attack_payload.exe",
        "behavior_score": behavior_score,
        "deception_triggered": deception_triggered,
        "final_risk": final_risk,
        "verdict": verdict,
        "rationale": rationale,
        "flags": [
            "Outbound command-and-control behavior detected",
            "Credential access attempt observed",
            "Privilege escalation sequence identified"
        ],
        "steps": steps,
        "soc_alerts": soc_alerts,
    }

    store_report(report)
    return render_report_html(report)
