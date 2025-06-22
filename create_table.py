import sqlite3

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

conn.commit()
conn.close()

print("✅ traffic_logs 테이블 생성 완료")
