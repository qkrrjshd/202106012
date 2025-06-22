import sqlite3
import random
from datetime import datetime, timedelta

# DB 연결 및 테이블 생성
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

# 예제 데이터 생성
labels = ["Normal", "DDoS", "PortScan", "BruteForce", "Botnet"]
protocols = ["TCP", "UDP", "ICMP"]
base_time = datetime.now() - timedelta(hours=2)

for i in range(200):
    ts = base_time + timedelta(seconds=i * 30)
    row = (
        ts.strftime("%Y-%m-%d %H:%M:%S"),
        f"192.168.0.{random.randint(1, 100)}",
        f"10.0.0.{random.randint(1, 100)}",
        random.choice(protocols),
        random.randint(50, 2000),
        round(random.uniform(60, 800), 2),
        round(random.uniform(1, 10), 2),
        round(random.uniform(0.2, 0.99), 2),
        random.choices(labels, weights=[0.5, 0.2, 0.1, 0.1, 0.1])[0]
    )
    cursor.execute("INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, protocol, packet_count, avg_packet_size, duration, confidence, label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", row)

conn.commit()
conn.close()
print("✅ logs.db에 예제 데이터 생성 완료!")
