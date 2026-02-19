"""
Report Generator
Produces a rich HTML report and a plain-text report from reconstructed messages + metadata.
"""

import os, json
from datetime import datetime


# ── HTML Report ─────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetCapture Pro — Traffic Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg:      #0a0e17;
    --panel:   #0f1623;
    --border:  #1e2d45;
    --cyan:    #00e5ff;
    --green:   #00ff9d;
    --yellow:  #ffd600;
    --red:     #ff4c7a;
    --text:    #c8d8f0;
    --dim:     #4a6080;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    line-height: 1.6;
  }}

  header {{
    background: linear-gradient(135deg, #0a0e17 0%, #0d1f35 100%);
    border-bottom: 2px solid var(--cyan);
    padding: 32px 40px;
    display: flex;
    align-items: center;
    gap: 24px;
  }}

  .logo {{
    font-family: 'Syne', sans-serif;
    font-size: 28px;
    font-weight: 800;
    color: var(--cyan);
    letter-spacing: -1px;
  }}
  .logo span {{ color: #fff; }}

  .meta-bar {{
    margin-left: auto;
    text-align: right;
    font-size: 11px;
    color: var(--dim);
  }}
  .meta-bar strong {{ color: var(--text); display: block; font-size: 13px; }}

  .badge {{
    display: inline-block;
    background: rgba(255,76,122,0.15);
    border: 1px solid var(--red);
    color: var(--red);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 3px;
    margin-top: 4px;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}

  main {{ padding: 32px 40px; max-width: 1400px; }}

  h2 {{
    font-family: 'Syne', sans-serif;
    font-size: 18px;
    font-weight: 700;
    color: var(--cyan);
    margin: 32px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
  }}

  /* Device card */
  .device-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 16px; }}
  .device-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-left: 3px solid var(--cyan);
    border-radius: 6px;
    padding: 18px 20px;
  }}
  .device-card .ip {{ font-size: 16px; color: var(--cyan); font-family: 'Syne', sans-serif; font-weight: 700; }}
  .device-card .row {{ display: flex; justify-content: space-between; margin-top: 6px; }}
  .device-card .label {{ color: var(--dim); }}
  .device-card .value {{ color: var(--text); text-align: right; max-width: 60%; word-break: break-all; }}
  .os-pill {{
    display: inline-block;
    background: rgba(0,229,255,0.1);
    border: 1px solid var(--cyan);
    color: var(--cyan);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 12px;
    margin-top: 8px;
  }}

  /* Traffic summary */
  .traffic-table {{ width: 100%; border-collapse: collapse; }}
  .traffic-table th {{
    background: var(--border);
    color: var(--cyan);
    font-family: 'Syne', sans-serif;
    text-align: left;
    padding: 10px 14px;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
  }}
  .traffic-table td {{ padding: 9px 14px; border-bottom: 1px solid var(--border); }}
  .traffic-table tr:hover td {{ background: rgba(0,229,255,0.04); }}
  .bar-wrap {{ background: var(--border); border-radius: 2px; height: 6px; width: 120px; }}
  .bar {{ height: 6px; border-radius: 2px; background: linear-gradient(90deg, var(--cyan), var(--green)); }}

  /* Messages */
  .platform-section {{ margin-bottom: 32px; }}
  .platform-title {{
    font-family: 'Syne', sans-serif;
    font-size: 15px;
    font-weight: 700;
    color: var(--green);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .msg-count {{
    background: rgba(0,255,157,0.1);
    border: 1px solid var(--green);
    color: var(--green);
    font-size: 10px;
    padding: 1px 7px;
    border-radius: 10px;
  }}

  .message-bubble {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px 18px;
    margin-bottom: 10px;
    position: relative;
  }}
  .message-bubble.sent   {{ border-left: 3px solid var(--green); }}
  .message-bubble.recv   {{ border-left: 3px solid var(--cyan);  }}
  .message-bubble.event  {{ border-left: 3px solid var(--yellow); }}
  .message-bubble.query  {{ border-left: 3px solid var(--dim);   }}

  .msg-header {{ display: flex; justify-content: space-between; margin-bottom: 6px; }}
  .msg-platform {{ color: var(--green); font-size: 11px; letter-spacing: 0.5px; }}
  .msg-time     {{ color: var(--dim);   font-size: 11px; }}
  .msg-from     {{ color: var(--cyan);  font-size: 12px; margin-bottom: 4px; }}
  .msg-content  {{ color: var(--text);  white-space: pre-wrap; word-break: break-word; }}

  /* DNS table */
  .dns-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  .dns-table td {{ padding: 5px 10px; border-bottom: 1px solid var(--border); }}
  .dns-table tr:nth-child(even) td {{ background: rgba(255,255,255,0.02); }}
  .dns-query {{ color: var(--yellow); }}
  .dns-src   {{ color: var(--dim); }}

  footer {{
    margin-top: 48px;
    padding: 24px 40px;
    border-top: 1px solid var(--border);
    color: var(--dim);
    font-size: 11px;
    display: flex;
    justify-content: space-between;
  }}
</style>
</head>
<body>
<header>
  <div>
    <div class="logo">Net<span>Capture</span> <span style="color:var(--dim)">Pro</span></div>
    <div class="badge">⚠ Authorized Use Only</div>
  </div>
  <div class="meta-bar">
    <strong>{target_ip}</strong>
    Generated: {generated}<br>
    Total Packets: {total_packets} &nbsp;|&nbsp; Captures: {capture_count}
  </div>
</header>
<main>

<!-- DEVICES -->
<h2>📡 Device Information</h2>
<div class="device-grid">
{device_cards}
</div>

<!-- TRAFFIC SUMMARY -->
<h2>📊 Traffic Summary</h2>
<table class="traffic-table">
  <tr>
    <th>Category</th><th>Packets</th><th>Bytes</th><th>Volume</th><th>Top Domains</th>
  </tr>
{traffic_rows}
</table>

<!-- MESSAGES -->
<h2>💬 Reconstructed Messages & Events</h2>
{message_sections}

</main>
<footer>
  <span>NetCapture Pro &mdash; Authorized Testing Tool</span>
  <span>Report generated {generated}</span>
</footer>
</body>
</html>"""


def _format_bytes(b):
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    return f"{b/1024**2:.1f} MB"


def _device_card(ip, dev):
    ports = ", ".join(str(p) for p in sorted(dev.get("open_ports",[]))[:8])
    hosts = ", ".join(list(dev.get("hostnames",[]))[:3])
    return f"""
<div class="device-card">
  <div class="ip">{ip}</div>
  <div class="row"><span class="label">MAC</span><span class="value">{dev.get('mac','—')}</span></div>
  <div class="row"><span class="label">Vendor</span><span class="value">{dev.get('vendor','Unknown')}</span></div>
  <div class="row"><span class="label">TTL</span><span class="value">{dev.get('ttl','—')}</span></div>
  {'<div class="row"><span class="label">Hostnames</span><span class="value">' + hosts + '</span></div>' if hosts else ''}
  {'<div class="row"><span class="label">Active Ports</span><span class="value">' + ports + '</span></div>' if ports else ''}
  <div class="os-pill">🖥 {dev.get('os_guess','Unknown')}</div>
</div>"""


def _traffic_row(cat, info, max_count):
    bar_pct = int(info['count'] / max(max_count, 1) * 100)
    domains  = ", ".join(list(info.get('domains',[]))[:4])
    return f"""  <tr>
    <td style="color:#00e5ff;font-weight:700">{cat}</td>
    <td>{info['count']:,}</td>
    <td>{_format_bytes(info['bytes'])}</td>
    <td><div class="bar-wrap"><div class="bar" style="width:{bar_pct}%"></div></div></td>
    <td style="color:#4a6080;font-size:11px">{domains[:80]}</td>
  </tr>"""


PLATFORM_ICONS = {
    "Facebook Messenger": "💬",
    "WhatsApp": "💚",
    "TextPlus": "📱",
    "VoIP / SIP": "📞",
    "XMPP/Jabber (Messaging)": "🟢",
    "DNS Queries": "🌐",
    "HTTP Requests": "🔗",
    "WebSocket Frames": "🔌",
}


def _message_section(platform, messages):
    icon = PLATFORM_ICONS.get(platform, "📨")
    bubbles = ""
    for msg in messages[:100]:
        content = msg.get("content","") or msg.get("query","") or msg.get("event","") or str(msg)
        sender  = msg.get("sender","") or msg.get("from","") or msg.get("src","")
        ts      = msg.get("timestamp","")
        direction = msg.get("direction","recv")
        cls = "sent" if direction == "sent" else ("event" if "event" in msg or "query" in msg else "recv")

        sender_html = f'<div class="msg-from">From: {sender}</div>' if sender else ""
        bubbles += f"""
<div class="message-bubble {cls}">
  <div class="msg-header">
    <span class="msg-platform">{icon} {platform}</span>
    <span class="msg-time">{ts}</span>
  </div>
  {sender_html}
  <div class="msg-content">{content[:400]}</div>
</div>"""

    overflow = f'<p style="color:#4a6080;margin:8px 0">... and {len(messages)-100} more items (see JSON for full data)</p>' if len(messages) > 100 else ""

    return f"""
<div class="platform-section">
  <div class="platform-title">{icon} {platform} <span class="msg-count">{len(messages)}</span></div>
  {bubbles}
  {overflow}
</div>"""


def generate_html(output_path: str, meta: dict, messages: dict) -> str:
    devices      = meta.get("devices", {})
    traffic_sum  = meta.get("traffic_summary", {})
    target_ip    = meta.get("target_ip", "Unknown")
    total_packets = meta.get("total_packets", 0)
    generated    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    device_cards = "\n".join(_device_card(ip, d) for ip, d in devices.items()) or "<p style='color:#4a6080'>No device data collected.</p>"

    max_count = max((v["count"] for v in traffic_sum.values()), default=1)
    traffic_rows = "\n".join(
        _traffic_row(cat, info, max_count)
        for cat, info in sorted(traffic_sum.items(), key=lambda x: -x[1]["count"])
    ) or "  <tr><td colspan='5' style='color:#4a6080;padding:20px'>No traffic data.</td></tr>"

    # Messages (exclude DNS if huge)
    msg_sections_html = ""
    for platform, msgs in messages.items():
        if not msgs:
            continue
        msg_sections_html += _message_section(platform, msgs)
    if not msg_sections_html:
        msg_sections_html = "<p style='color:#4a6080'>No messages reconstructed. Capture may be encrypted — use the Decrypt module.</p>"

    html = HTML_TEMPLATE.format(
        target_ip=target_ip,
        generated=generated,
        total_packets=f"{total_packets:,}",
        capture_count=len(traffic_sum),
        device_cards=device_cards,
        traffic_rows=traffic_rows,
        message_sections=msg_sections_html,
    )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def generate_txt(output_path: str, meta: dict, messages: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("  NetCapture Pro — Human Readable Traffic Report")
    lines.append(f"  Target IP  : {meta.get('target_ip','?')}")
    lines.append(f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  Total Pkts : {meta.get('total_packets',0):,}")
    lines.append("=" * 70)

    # Devices
    lines.append("\n── DEVICE INFORMATION ──\n")
    for ip, dev in meta.get("devices",{}).items():
        lines.append(f"  IP       : {ip}")
        lines.append(f"  MAC      : {dev.get('mac','—')}")
        lines.append(f"  Vendor   : {dev.get('vendor','Unknown')}")
        lines.append(f"  OS Guess : {dev.get('os_guess','Unknown')} (TTL={dev.get('ttl','?')})")
        lines.append(f"  Ports    : {', '.join(str(p) for p in sorted(dev.get('open_ports',[]))[:10])}")
        lines.append(f"  Hosts    : {', '.join(list(dev.get('hostnames',[]))[:5])}")
        lines.append("")

    # Traffic
    lines.append("── TRAFFIC SUMMARY ──\n")
    for cat, info in sorted(meta.get("traffic_summary",{}).items(), key=lambda x: -x[1]["count"]):
        lines.append(f"  [{cat}]")
        lines.append(f"    Packets : {info['count']:,}  |  Bytes: {_format_bytes(info['bytes'])}")
        if info.get("domains"):
            lines.append(f"    Domains : {', '.join(list(info['domains'])[:5])}")
        lines.append("")

    # Messages
    lines.append("── RECONSTRUCTED MESSAGES ──\n")
    for platform, msgs in messages.items():
        if not msgs:
            continue
        lines.append(f"  ▶ {platform} ({len(msgs)} items)")
        lines.append("  " + "─" * 50)
        for msg in msgs[:50]:
            ts      = msg.get("timestamp","")
            sender  = msg.get("sender","") or msg.get("from","") or msg.get("src","")
            content = msg.get("content","") or msg.get("query","") or msg.get("event","") or ""
            if ts:     lines.append(f"  Time    : {ts}")
            if sender: lines.append(f"  From    : {sender}")
            if content:lines.append(f"  Content : {content[:300]}")
            lines.append("")
        if len(msgs) > 50:
            lines.append(f"  ... and {len(msgs)-50} more items\n")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return output_path
