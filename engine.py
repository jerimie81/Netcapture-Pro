"""Core traffic capture & device discovery engine."""

import os, time, json, threading
from datetime import datetime
from collections import defaultdict

from scapy.all import (
    sniff, wrpcap, ARP, IP, TCP, UDP, DNS, DNSQR, Ether,
    get_if_list, conf
)

# ── Traffic signatures ──────────────────────────────────
SIGNATURES = {
    "Social Media": {
        "domains": ["facebook.com","instagram.com","twitter.com","x.com","tiktok.com",
                    "snapchat.com","reddit.com","linkedin.com","pinterest.com"],
        "ports": []
    },
    "Messaging": {
        "domains": ["whatsapp.com","telegram.org","signal.org","discord.com",
                    "messenger.com","textplus.com","viber.com","line.me"],
        "ports": [5222, 5223, 4244]
    },
    "VoIP": {
        "domains": ["zoom.us","teams.microsoft.com","meet.google.com","skype.com",
                    "webex.com","vonage.com"],
        "ports": [5060, 5061, 16384, 16482]  # SIP, RTP ranges
    },
    "Video Streaming": {
        "domains": ["netflix.com","youtube.com","hulu.com","disneyplus.com",
                    "hbomax.com","twitch.tv","primevideo.com","peacocktv.com"],
        "ports": [1935, 554]
    },
    "Music Streaming": {
        "domains": ["spotify.com","music.apple.com","soundcloud.com","pandora.com",
                    "tidal.com","deezer.com"],
        "ports": []
    },
    "Gaming": {
        "domains": ["steam.valve.com","epicgames.com","battle.net","ea.com","roblox.com"],
        "ports": [27015, 3074, 9308]
    },
    "Email": {
        "domains": ["gmail.com","outlook.com","yahoo.com","protonmail.com"],
        "ports": [25, 110, 143, 465, 587, 993, 995]
    },
    "Web (HTTP)":  {"domains": [], "ports": [80]},
    "Web (HTTPS)": {"domains": [], "ports": [443]},
    "DNS":  {"domains": [], "ports": [53]},
    "SSH":  {"domains": [], "ports": [22]},
    "FTP":  {"domains": [], "ports": [20, 21]},
    "VPN":  {"domains": [], "ports": [1194, 1723, 500, 4500]},
    "Other": {"domains": [], "ports": []},
}

try:
    import manuf
    _mac_parser = manuf.MacParser()
except Exception:
    _mac_parser = None


def mac_vendor(mac):
    if _mac_parser and mac:
        try:
            v = _mac_parser.get_manuf(mac)
            return v or "Unknown"
        except Exception:
            pass
    return "Unknown"


def guess_os(ttl):
    if ttl is None:
        return "Unknown"
    if 55 <= ttl <= 65:
        return "Linux / Android / macOS"
    elif 120 <= ttl <= 128:
        return "Windows"
    elif 250 <= ttl <= 255:
        return "iOS / Network Device"
    return f"Unknown (TTL={ttl})"


def classify_packet(pkt):
    ports, domains = set(), set()
    if IP not in pkt:
        return "Other", domains
    if TCP in pkt:
        ports |= {pkt[TCP].dport, pkt[TCP].sport}
    if UDP in pkt:
        ports |= {pkt[UDP].dport, pkt[UDP].sport}
    if DNS in pkt and pkt[DNS].qr == 0:
        try:
            domains.add(pkt[DNSQR].qname.decode().rstrip("."))
        except Exception:
            pass
    for cat, sig in SIGNATURES.items():
        if cat == "Other":
            continue
        for d in sig["domains"]:
            for qd in domains:
                if d in qd:
                    return cat, domains
        for p in sig["ports"]:
            if p in ports:
                return cat, domains
    return "Other", domains


class CaptureEngine:
    def __init__(self, target_ip: str, iface: str = None):
        self.target_ip    = target_ip
        self.iface        = iface or self._best_iface()
        self.traffic      = defaultdict(lambda: {
            "count": 0, "bytes": 0, "ports": set(), "domains": set()
        })
        self.devices      = {}
        self.all_packets  = []
        self._stop        = threading.Event()

    def _best_iface(self):
        for i in get_if_list():
            if i != "lo":
                return i
        return conf.iface

    def arp_scan(self):
        from scapy.all import srp
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_ip),
                timeout=2, verbose=0, iface=self.iface
            )
            for _, r in ans:
                return r[Ether].src
        except Exception:
            pass
        return None

    def _handle(self, pkt):
        if IP not in pkt:
            return
        src, dst = pkt[IP].src, pkt[IP].dst
        if src != self.target_ip and dst != self.target_ip:
            return
        self.all_packets.append(pkt)

        active_ip = src if src == self.target_ip else dst
        mac = pkt[Ether].src if Ether in pkt else None
        dev = self.devices.setdefault(active_ip, {
            "ip": active_ip, "mac": None, "vendor": "Unknown",
            "os_guess": "Unknown", "ttl": None,
            "hostnames": set(), "open_ports": set()
        })
        if mac and not dev["mac"]:
            dev["mac"]    = mac
            dev["vendor"] = mac_vendor(mac)
        if dev["ttl"] is None:
            dev["ttl"]      = pkt[IP].ttl
            dev["os_guess"] = guess_os(pkt[IP].ttl)
        if DNS in pkt:
            try:
                dev["hostnames"].add(pkt[DNSQR].qname.decode().rstrip("."))
            except Exception:
                pass
        if TCP in pkt:
            dev["open_ports"].add(pkt[TCP].dport)
        if UDP in pkt:
            dev["open_ports"].add(pkt[UDP].dport)

        cat, domains = classify_packet(pkt)
        self.traffic[cat]["count"] += 1
        self.traffic[cat]["bytes"] += len(pkt)
        self.traffic[cat]["domains"] |= domains
        if TCP in pkt:
            self.traffic[cat]["ports"].add(pkt[TCP].dport)
        if UDP in pkt:
            self.traffic[cat]["ports"].add(pkt[UDP].dport)

    def sniff(self, duration: int, progress_cb=None):
        """Sniff for `duration` seconds, calling progress_cb(elapsed) each second."""
        self._stop.clear()
        def _run():
            sniff(iface=self.iface,
                  filter=f"host {self.target_ip}",
                  prn=self._handle,
                  store=False,
                  timeout=duration,
                  stop_filter=lambda _: self._stop.is_set())
        t = threading.Thread(target=_run, daemon=True)
        t.start()
        for i in range(duration):
            if self._stop.is_set():
                break
            time.sleep(1)
            if progress_cb:
                progress_cb(i + 1, duration,
                            sum(v["count"] for v in self.traffic.values()),
                            sum(v["bytes"] for v in self.traffic.values()))
        self._stop.set()
        t.join(timeout=3)

    def stop(self):
        self._stop.set()

    def save_pcap(self, path: str, filter_categories: list = None):
        """Save all_packets (optionally filtered) to pcap."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        pkts = self.all_packets
        if filter_categories:
            # Re-classify each packet against selected categories
            filtered = []
            for pkt in pkts:
                cat, _ = classify_packet(pkt)
                if cat in filter_categories:
                    filtered.append(pkt)
            pkts = filtered
        if pkts:
            wrpcap(path, pkts)
        return len(pkts)

    def save_meta(self, path: str, extra: dict = None):
        meta = {
            "target_ip":  self.target_ip,
            "interface":  self.iface,
            "timestamp":  datetime.now().isoformat(),
            "total_packets": len(self.all_packets),
            "traffic_summary": {
                cat: {
                    "count":   v["count"],
                    "bytes":   v["bytes"],
                    "ports":   list(v["ports"]),
                    "domains": list(v["domains"]),
                }
                for cat, v in self.traffic.items() if v["count"] > 0
            },
            "devices": {
                ip: {
                    "mac":        d["mac"],
                    "vendor":     d["vendor"],
                    "os_guess":   d["os_guess"],
                    "ttl":        d["ttl"],
                    "hostnames":  list(d["hostnames"]),
                    "open_ports": list(d["open_ports"]),
                }
                for ip, d in self.devices.items()
            }
        }
        if extra:
            meta.update(extra)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(meta, f, indent=2)
        return meta

    def active_traffic(self):
        return {k: v for k, v in self.traffic.items() if v["count"] > 0}
