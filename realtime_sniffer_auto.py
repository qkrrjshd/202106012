import argparse
import sqlite3
from datetime import datetime
from scapy.all import sniff, get_working_ifaces, IP
import random

# 데이터베이스 저장 함수
def save_to_db(timestamp, src_ip, dst_ip, proto, packet_count, avg_size, duration, confidence, label):
    conn = sqlite3.connect("logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            packet_count INTEGER,
            avg_packet_size REAL,
            duration REAL,
            confidence REAL,
            label TEXT
        )
    """)
    cursor.execute("""
        INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, protocol, packet_count, avg_packet_size, duration, confidence, label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, proto, packet_count, avg_size, duration, confidence, label))
    conn.commit()
    conn.close()

# 패킷 수집 및 분석 함수
def process(pkt):
    if IP in pkt:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        packet_count = random.randint(10, 100)
        avg_size = random.uniform(60, 1500)
        duration = random.uniform(1, 100)
        confidence = random.uniform(0.5, 1.0)
        label = "Attack" if confidence > 0.75 else "Normal"
        save_to_db(now, src, dst, str(proto), packet_count, avg_size, duration, confidence, label)
        print(f"[+] {now} {src} -> {dst} [{label}]")

# 자동 인터페이스 선택
def auto_select_interface():
    interfaces = get_working_ifaces()
    for iface in interfaces:
        if "Wi-Fi" in iface.description or "Ethernet" in iface.description:
            return iface.name
    return interfaces[0].name if interfaces else None

def main():
    iface_name = auto_select_interface()
    if not iface_name:
        print("[ERROR] 사용할 수 있는 네트워크 인터페이스를 찾을 수 없습니다.")
        return
    print(f"[*] 감지 시작 - 인터페이스: {iface_name}")
    sniff(iface=iface_name, prn=process, store=False, filter="ip")

if __name__ == "__main__":
    main()
