#!/usr/bin/env python3
"""
Real-time packet sniffer  →  feature extractor  →  FastAPI predictor
"""
import argparse, queue, threading, os
from collections import defaultdict
from typing import Tuple

import requests
from scapy.all import sniff, IP
from tenacity import retry, wait_fixed, stop_after_attempt
from dotenv import load_dotenv

# ───────── 설정 ─────────────────────────────────────────────
load_dotenv()
API_URL = os.getenv("API_URL", "http://127.0.0.1:8001/predict/ddos")
JWT_TOKEN = os.getenv("JWT_TOKEN")
FLUSH_SEC = 1.0
TX_Q = queue.Queue(maxsize=10_000)

# ───────── 1) 패킷 → 플로우 집계 ────────────────────────────
flows = defaultdict(lambda: {"first": 0.0, "fwd": 0, "bwd": 0})

def process(pkt):
    if IP not in pkt:
        return

    key: Tuple = (
        pkt[IP].src, pkt[IP].dst,
        getattr(pkt, "sport", 0), getattr(pkt, "dport", 0),
        pkt.proto,
    )
    now = pkt.time
    f = flows[key]

    if f["first"] == 0:
        f["first"] = now

    if pkt[IP].src == key[0]:
        f["fwd"] += 1
    else:
        f["bwd"] += 1

    if now - f["first"] >= FLUSH_SEC:
        duration_us = int((now - f["first"]) * 1_000_000)
        fwd = f["fwd"]
        bwd = f["bwd"]
        TX_Q.put({
            "features": [duration_us, fwd, bwd],
            "src_ip": key[0]
        })
        del flows[key]

# ───────── 2) API 전송 스레드 ──────────────────────────────
@retry(wait=wait_fixed(2), stop=stop_after_attempt(3))
def post_predict(payload):
    headers = {"Authorization": JWT_TOKEN}
    r = requests.post(API_URL, json=payload, headers=headers, timeout=2)
    r.raise_for_status()

def sender():
    while True:
        item = TX_Q.get()
        try:
            post_predict(item)
        except Exception as e:
            print("[Sender] error:", e)

# ───────── 3) 엔트리포인트 ─────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", default="Wi-Fi", help="capture interface name")
    args = ap.parse_args()

    threading.Thread(target=sender, daemon=True).start()
    print(f"[Sniffer] start on {args.iface}")
    sniff(iface=args.iface, prn=process, store=False, filter="ip")

if __name__ == "__main__":
    main()
