"""
Decryption Engine
- SSL/TLS via SSLKEYLOGFILE (Wireshark-compatible)
- Attempt WEP/WPA2-PSK Wi-Fi decryption via tshark
- Extract & display TLS certificates
- Detect and decode Base64, URL-encoded payloads
- Attempt common protocol decryption (SIP, RTSP)
"""

import os, re, json, base64, subprocess, tempfile, binascii
from urllib.parse import unquote_plus
from datetime import datetime


# ── TLS/SSL via key log file ─────────────────────────────

def decrypt_tls_with_keylog(pcap_path: str, keylog_path: str, output_dir: str) -> dict:
    """
    Use tshark + SSLKEYLOGFILE to decrypt TLS streams.
    Returns {"success": bool, "output_file": str, "message": str}
    """
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_pcap = os.path.join(output_dir, f"decrypted_tls_{ts}.pcap")
    out_txt  = os.path.join(output_dir, f"decrypted_tls_{ts}.txt")

    # tshark decrypt to pcap
    cmd_pcap = [
        "tshark", "-r", pcap_path,
        "-o", f"tls.keylog_file:{keylog_path}",
        "-w", out_pcap
    ]
    # tshark export HTTP/2 and HTTP objects
    cmd_txt = [
        "tshark", "-r", pcap_path,
        "-o", f"tls.keylog_file:{keylog_path}",
        "-Y", "http or http2 or data-text-lines",
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.uri",
        "-e", "http.request.method",
        "-e", "http2.headers.path",
        "-e", "data-text-lines",
    ]

    results = {
        "success": False,
        "output_pcap": out_pcap,
        "output_txt":  out_txt,
        "message": "",
        "records": []
    }

    try:
        r = subprocess.run(cmd_pcap, capture_output=True, timeout=60)
        if r.returncode == 0 and os.path.exists(out_pcap):
            results["success"] = True
            results["message"] = f"Decrypted pcap saved: {out_pcap}"

        r2 = subprocess.run(cmd_txt, capture_output=True, text=True, timeout=60)
        lines = [l for l in r2.stdout.splitlines() if l.strip()]
        with open(out_txt, "w") as f:
            f.write("=== TLS Decrypted Traffic ===\n\n")
            for line in lines:
                f.write(line + "\n")
        results["records"] = lines[:200]
        if not results["message"]:
            results["message"] = f"Decrypted text saved: {out_txt}"
    except FileNotFoundError:
        results["message"] = "tshark not found. Install: sudo apt install tshark"
    except subprocess.TimeoutExpired:
        results["message"] = "Decryption timed out."
    except Exception as e:
        results["message"] = str(e)

    return results


# ── Wi-Fi WPA2-PSK decryption via tshark ─────────────────

def decrypt_wifi_wpa2(pcap_path: str, psk: str, ssid: str, output_dir: str) -> dict:
    """Decrypt WPA2-PSK Wi-Fi traffic using tshark."""
    os.makedirs(output_dir, exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_txt = os.path.join(output_dir, f"decrypted_wifi_{ts}.txt")

    # tshark wpa decryption key format: wpa-pwd:PSK:SSID
    key = f"wpa-pwd:{psk}:{ssid}"
    cmd = [
        "tshark", "-r", pcap_path,
        "-o", f"wlan.enable_decryption:TRUE",
        "-o", f"uat:80211_keys:\"wpa-pwd\",\"{psk}:{ssid}\"",
        "-Y", "http or data",
        "-T", "fields",
        "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.host", "-e", "http.request.uri",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        lines = [l for l in r.stdout.splitlines() if l.strip()]
        with open(out_txt, "w") as f:
            f.write(f"=== WPA2-PSK Decrypted Wi-Fi Traffic ===\n")
            f.write(f"SSID: {ssid}  |  PSK: {'*' * len(psk)}\n\n")
            for line in lines:
                f.write(line + "\n")
        return {"success": True, "output": out_txt, "records": lines[:200]}
    except FileNotFoundError:
        return {"success": False, "message": "tshark not found. Install: sudo apt install tshark"}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ── Payload decoder ──────────────────────────────────────

def decode_payload(raw: str) -> dict:
    """Attempt to decode a raw payload string via multiple methods."""
    results = {}

    # Base64
    try:
        stripped = re.sub(r"\s", "", raw)
        decoded  = base64.b64decode(stripped + "==").decode("utf-8", errors="replace")
        if len(decoded) > 4 and decoded.isprintable():
            results["base64"] = decoded[:2000]
    except Exception:
        pass

    # URL-encoded
    try:
        decoded = unquote_plus(raw)
        if decoded != raw:
            results["url_decoded"] = decoded[:2000]
    except Exception:
        pass

    # Hex
    try:
        stripped = raw.replace(" ","").replace(":","")
        if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0:
            decoded = bytes.fromhex(stripped).decode("utf-8", errors="replace")
            results["hex_decoded"] = decoded[:2000]
    except Exception:
        pass

    # JSON pretty-print
    try:
        jdata = json.loads(raw)
        results["json"] = json.dumps(jdata, indent=2)[:2000]
    except Exception:
        pass

    if not results:
        results["raw"] = raw[:2000]

    return results


# ── TLS Certificate extraction ───────────────────────────

def extract_certificates(pcap_path: str, output_dir: str) -> list:
    """Extract TLS certificates from a pcap using tshark."""
    os.makedirs(output_dir, exist_ok=True)
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "tls.handshake.certificate",
        "-T", "fields",
        "-e", "frame.time",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "x509sat.uTF8String",
        "-e", "x509ce.dNSName",
    ]
    certs = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 5 and any(parts[3:]):
                certs.append({
                    "time": parts[0],
                    "src":  parts[1],
                    "dst":  parts[2],
                    "cn":   parts[3],
                    "san":  parts[4] if len(parts) > 4 else "",
                })
    except Exception:
        pass
    return certs


# ── RTSP stream URL extraction ───────────────────────────

def extract_rtsp(pcap_path: str) -> list:
    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "rtsp",
        "-T", "fields",
        "-e", "frame.time", "-e", "rtsp.url", "-e", "rtsp.method",
    ]
    streams = []
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1]:
                streams.append({"time": parts[0], "url": parts[1], "method": parts[2] if len(parts)>2 else ""})
    except Exception:
        pass
    return streams
