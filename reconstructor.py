"""
Message Reconstruction Engine
Reconstructs human-readable messages from captured pcap traffic.
Supports: HTTP plaintext, DNS queries, SIP/VoIP metadata, WebSocket frames,
XMPP (Jabber/WhatsApp protocol base), multipart payloads.
"""

import re, json, base64, gzip, zlib
from datetime  import datetime
from urllib.parse import unquote_plus, urlparse

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
    SCAPY = True
except ImportError:
    SCAPY = False


# ── Helpers ─────────────────────────────────────────────

def _ts(pkt):
    try:
        return datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Unknown"

def _decode_body(data: bytes, encoding: str = "") -> str:
    try:
        if "gzip" in encoding:
            data = gzip.decompress(data)
        elif "deflate" in encoding:
            data = zlib.decompress(data)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return data.decode("latin-1", errors="replace")

def _parse_http(raw: bytes):
    """Very lightweight HTTP/1.x parser. Returns dict or None."""
    try:
        text = raw.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None
        first = lines[0]
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        body = "\r\n".join(lines[body_start:]) if body_start else ""

        if first.startswith(("GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS")):
            method, path, *_ = first.split(" ", 2)
            return {
                "type":    "request",
                "method":  method,
                "path":    path,
                "headers": headers,
                "body":    body,
            }
        elif first.startswith("HTTP"):
            _, code, *reason = first.split(" ", 2)
            return {
                "type":     "response",
                "status":   code,
                "reason":   " ".join(reason),
                "headers":  headers,
                "body":     body,
                "encoding": headers.get("content-encoding", ""),
            }
    except Exception:
        pass
    return None


def _extract_ws_frames(payload: bytes):
    """Minimal WebSocket frame parser."""
    frames = []
    i = 0
    while i + 2 <= len(payload):
        try:
            b0, b1 = payload[i], payload[i+1]
            opcode  = b0 & 0x0F
            masked  = (b1 & 0x80) != 0
            length  = b1 & 0x7F
            i += 2
            if length == 126:
                length = int.from_bytes(payload[i:i+2], "big"); i += 2
            elif length == 127:
                length = int.from_bytes(payload[i:i+8], "big"); i += 8
            mask = payload[i:i+4] if masked else b"\x00\x00\x00\x00"
            if masked: i += 4
            data = payload[i:i+length]
            if masked:
                data = bytes(b ^ mask[j % 4] for j, b in enumerate(data))
            i += length
            if opcode in (1, 2):  # text / binary
                frames.append(data.decode("utf-8", errors="replace"))
        except Exception:
            break
    return frames


def _sip_parse(raw: bytes):
    """Minimal SIP message parser."""
    try:
        text = raw.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines[0].startswith(("SIP/","INVITE","ACK","BYE","REGISTER","OPTIONS","NOTIFY")):
            return None
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return {
            "type":    "sip",
            "first":   lines[0],
            "from":    headers.get("from", ""),
            "to":      headers.get("to", ""),
            "call_id": headers.get("call-id", ""),
            "subject": headers.get("subject", ""),
        }
    except Exception:
        return None


def _xmpp_parse(raw: bytes):
    """Extract text from XMPP/Jabber XML (WhatsApp uses a binary variant, but base XMPP is XML)."""
    try:
        text = raw.decode("utf-8", errors="replace")
        bodies = re.findall(r"<body[^>]*>(.*?)</body>", text, re.DOTALL)
        froms  = re.findall(r'from=["\']([^"\']+)["\']', text)
        tos    = re.findall(r'\bto=["\']([^"\']+)["\']', text)
        if bodies:
            return {"type": "xmpp", "from": froms[0] if froms else "", "to": tos[0] if tos else "", "bodies": bodies}
    except Exception:
        pass
    return None


# ── Facebook Messenger (Graph API & website) ─────────────

def parse_facebook(http_obj, ts):
    msgs = []
    if not http_obj:
        return msgs
    path = http_obj.get("path", "")
    body = http_obj.get("body", "")
    headers = http_obj.get("headers", {})
    ct = headers.get("content-type", "")

    # Messenger send endpoint
    if "/messaging" in path or "message_send" in path.lower():
        body_text = unquote_plus(body)
        m = re.search(r"body=([^&]+)", body_text)
        if m:
            msgs.append({
                "platform": "Facebook Messenger",
                "timestamp": ts,
                "direction": "sent",
                "content":  unquote_plus(m.group(1)),
            })
    # Graph API messages
    if "graph.facebook.com" in headers.get("host","") and "messages" in path:
        try:
            jdata = json.loads(body)
            for item in jdata.get("data", []):
                msgs.append({
                    "platform":  "Facebook Messenger",
                    "timestamp": item.get("created_time", ts),
                    "sender":    item.get("from", {}).get("name", "Unknown"),
                    "content":   item.get("message",""),
                })
        except Exception:
            pass
    return msgs


def parse_whatsapp(http_obj, raw_payload, ts):
    msgs = []
    if not http_obj and not raw_payload:
        return msgs
    # WhatsApp Web uses WebSocket frames
    if raw_payload:
        frames = _extract_ws_frames(raw_payload)
        for frame in frames:
            # WhatsApp Web JSON messages contain type & body
            try:
                jdata = json.loads(frame)
                # Format 1: array messages
                if isinstance(jdata, list) and len(jdata) >= 2:
                    tag, data = jdata[0], jdata[1]
                    if isinstance(data, dict) and "body" in data:
                        msgs.append({
                            "platform":  "WhatsApp",
                            "timestamp": ts,
                            "tag":       tag,
                            "content":   data["body"],
                            "from":      data.get("key",{}).get("remoteJid",""),
                        })
            except Exception:
                # Try plain text frame
                if len(frame) > 2 and not frame.startswith("<"):
                    msgs.append({
                        "platform":  "WhatsApp (raw frame)",
                        "timestamp": ts,
                        "content":   frame[:500],
                    })
    return msgs


def parse_textplus(http_obj, ts):
    msgs = []
    if not http_obj:
        return msgs
    path = http_obj.get("path","")
    body = http_obj.get("body","")
    if "textplus" in http_obj.get("headers",{}).get("host",""):
        if "/messages" in path or "/send" in path:
            body_dec = unquote_plus(body)
            m = re.search(r'"body"\s*:\s*"([^"]+)"', body_dec)
            if m:
                msgs.append({
                    "platform":  "TextPlus",
                    "timestamp": ts,
                    "direction": "sent",
                    "content":   m.group(1),
                })
    return msgs


def parse_sip_voip(raw_payload, ts):
    msgs = []
    parsed = _sip_parse(raw_payload)
    if parsed:
        msgs.append({
            "platform":  "VoIP/SIP",
            "timestamp": ts,
            "event":     parsed["first"],
            "from":      parsed["from"],
            "to":        parsed["to"],
            "call_id":   parsed["call_id"],
            "subject":   parsed["subject"],
        })
    return msgs


def parse_dns(pkt, ts):
    msgs = []
    if DNS in pkt and pkt[DNS].qr == 0:
        try:
            name = pkt[DNSQR].qname.decode().rstrip(".")
            msgs.append({
                "platform":  "DNS Query",
                "timestamp": ts,
                "query":     name,
                "src":       pkt[IP].src if IP in pkt else "",
            })
        except Exception:
            pass
    return msgs


# ── Main reconstruct function ────────────────────────────

def reconstruct(pcap_path: str, categories: list = None) -> dict:
    """
    Load pcap and reconstruct messages.
    Returns dict: { platform_name: [message_dict, ...] }
    """
    if not SCAPY:
        return {"error": ["Scapy not available"]}

    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return {"error": [{"content": str(e)}]}

    results = {}

    def add(platform, msg):
        results.setdefault(platform, []).append(msg)

    for pkt in packets:
        ts = _ts(pkt)
        raw = bytes(pkt[Raw].load) if Raw in pkt else b""

        # ── DNS ───────────────────────────────────────────
        if DNS in pkt:
            for m in parse_dns(pkt, ts):
                add("DNS Queries", m)
            continue

        # ── SIP/VoIP ─────────────────────────────────────
        if UDP in pkt and raw and pkt[UDP].dport in (5060,5061) or pkt[UDP].sport in (5060,5061) if UDP in pkt else False:
            for m in parse_sip_voip(raw, ts):
                add("VoIP / SIP", m)
            continue

        if not raw:
            continue

        # ── HTTP parse ────────────────────────────────────
        http = _parse_http(raw)
        host = ""
        if http:
            host = http.get("headers",{}).get("host","")

        # ── Route to platform parsers ─────────────────────
        is_fb   = "facebook" in host or "messenger" in host
        is_wa   = "whatsapp" in host
        is_tp   = "textplus" in host
        is_xmpp = False

        if is_fb:
            for m in parse_facebook(http, ts):
                add("Facebook Messenger", m)

        if is_wa:
            for m in parse_whatsapp(http, raw, ts):
                add("WhatsApp", m)

        if is_tp:
            for m in parse_textplus(http, ts):
                add("TextPlus", m)

        # XMPP (port 5222)
        if TCP in pkt and pkt[TCP].dport in (5222, 5223):
            xmpp = _xmpp_parse(raw)
            if xmpp:
                for body in xmpp["bodies"]:
                    add("XMPP/Jabber (Messaging)", {
                        "platform":  "XMPP",
                        "timestamp": ts,
                        "from":      xmpp["from"],
                        "to":        xmpp["to"],
                        "content":   body,
                    })

        # WebSocket generic
        if TCP in pkt and pkt[TCP].dport in (80, 443, 8080):
            frames = _extract_ws_frames(raw)
            if frames:
                for frame in frames[:5]:
                    add("WebSocket Frames", {
                        "platform":  "WebSocket",
                        "timestamp": ts,
                        "host":      host,
                        "content":   frame[:300],
                    })

        # Generic HTTP requests (log URLs)
        if http and http["type"] == "request" and not (is_fb or is_wa or is_tp):
            path = http.get("path","")
            if path and path != "/":
                add("HTTP Requests", {
                    "platform":  "HTTP",
                    "timestamp": ts,
                    "method":    http.get("method",""),
                    "host":      host,
                    "path":      path[:120],
                    "user_agent": http.get("headers",{}).get("user-agent",""),
                })

    return results
