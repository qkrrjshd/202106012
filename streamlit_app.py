# 202106012
from utils import send_email_alert
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sqlite3
from datetime import datetime, timedelta
import pydeck as pdk
from streamlit_autorefresh import st_autorefresh
import requests
import random

# ------------------ 페이지 설정 ------------------
st.set_page_config(
    page_title="DDoS 탑지 및 경보 대시보드",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ------------------ 로그인 기능 ------------------
def show_login():
    st.title("🔐 로그인 또는 회원가입")
    page = st.radio("작업 선택:", ["로그인", "회원가입"])

    conn = sqlite3.connect("logs.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()

    if page == "회원가입":
        new_user = st.text_input("사용자 이름")
        new_pass = st.text_input("비밀번호", type="password")
        if st.button("회원가입 완료"):
            c.execute("SELECT * FROM users WHERE username=?", (new_user,))
            if c.fetchone():
                st.warning("이미 존재하는 사용자입니다.")
            else:
                c.execute("INSERT INTO users (username, password) VALUES (?, ?) ", (new_user, new_pass))
                conn.commit()
                st.success("회원가입 완료! 로그인 해주세요.")
            st.stop()

    elif page == "로그인":
        user = st.text_input("사용자 이름")
        pw = st.text_input("비밀번호", type="password")
        if st.button("로그인"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pw))
            result = c.fetchone()
            conn.close()
            if result:
                st.session_state.logged_in = True
                st.session_state.username = user
                st.success(f"{user}님 환영합니다!")
                st.rerun()
            else:
                st.error("로그인 실패. 정보를 확인해주세요.")
                st.stop()

# ------------------ 로그인 확인 ------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    show_login()
    st.stop()

# ------------------ 대시보드 UI 설정 ------------------
st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR&display=swap" rel="stylesheet">
<style>
    html, body, [class*="css"]  {
        font-family: 'Noto Sans KR', sans-serif !important;
    }
</style>
""", unsafe_allow_html=True)

PRIMARY_COLOR = "#FF5733"
TEXT_COLOR = "#FFFFFF"
BACKGROUND_COLOR = "#111111"
CHART_BG_COLOR = "#111111"

st.markdown(f"""
<style>
    body {{ background-color: {BACKGROUND_COLOR}; color: {TEXT_COLOR}; }}
    .metric-label {{ font-size: 22px !important; color: #00FFFF !important; font-weight: 900 !important; text-shadow: 0px 0px 3px rgba(0, 255, 255, 0.7); }}
    .metric-value {{ font-size: 32px !important; color: #FFCC00 !important; font-weight: 900 !important; text-shadow: 0px 0px 4px rgba(255, 204, 0, 0.9); }}
    .block-container {{ padding: 3rem 2rem 2rem 2rem; }}
</style>
""", unsafe_allow_html=True)

# ------------------ 실시간 새로고침 및 시간 출력 ------------------
st_autorefresh(interval=10000, key="auto_refresh")
now = datetime.now()
st.markdown(f"""
<div style='text-align:right;'>
    <span style='color:lightgray; font-size:24px; font-weight:800;'>🕒 현재 시간: {now.strftime('%Y-%m-%d %H:%M:%S')}</span>
</div>
""", unsafe_allow_html=True)

# ------------------ 대시보드 헤더 ------------------
st.markdown(f"""
<div style='text-align:center; padding: 10px 0;'>
    <h1 style='color:{PRIMARY_COLOR}; font-size:48px;'>🚨 DDoS 탐지 및 경보 대시보드 🚨</h1>
    <p style='color:{TEXT_COLOR}; font-size:16px;'>AI 기반 위협 분석으로 보안 강화</p>
</div>
<hr style='border:2px solid {PRIMARY_COLOR}; margin-top:10px;'>
""", unsafe_allow_html=True)

# ------------------ 공인 IP 생성 함수 ------------------
def generate_random_public_ip():
    while True:
        a = random.randint(1, 223)
        if a in [10, 127, 172, 192]:
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

# ------------------ 랜덤 예측 샘플 추가 ------------------
if st.button("🔄 랜덤 예측 샘플 추가"):
    conn = sqlite3.connect("logs.db")
    c = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    random_ip = generate_random_public_ip()

    # 랜덤 공격 종류 및 위험도 생성
    label = random.choice(["DDoS", "Port Scan", "Botnet", "Brute Force"])
    confidence = round(random.uniform(0.6, 1.0), 2)
    duration = random.randint(10, 100)

    c.execute("""
        INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, label, confidence, duration)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (now_str, random_ip, "10.0.0.1", label, confidence, duration))
    conn.commit()
    conn.close()

    if confidence >= 0.9:
        response_msg = "🚨 고위험! 즉시 차단 조치 필요"
    elif confidence >= 0.8:
        response_msg = "⚠️ 중위험! 실시간 모니터링 필요"
    else:
        response_msg = "🔍 저위험. 추적 감시 대상"

    st.success("✅ 랜덤 예측 샘플이 추가되었습니다.")
    st.markdown(f"""
    ### 🔍 예측 결과 요약
    - 🕵️‍♂️ **공격 IP**: `{random_ip}`
    - 🛠 **공격 종류**: `{label}`
    - 🎯 **위험도 점수**: `{confidence}`
    - ⏱ **예상 지속 시간**: `{duration} 초`
    - 🛡 **대응 메시지**: `{response_msg}`
    """)

# ------------------ 트래픽 막대그래프 ------------------
data = pd.DataFrame({
    'timestamp': pd.date_range(start=now - timedelta(hours=1), periods=12, freq='5min'),
    'volume': np.random.randint(20, 100, size=12)
})

fig, ax = plt.subplots(figsize=(14, 6))
bars = ax.bar(
    data['timestamp'].dt.strftime('%H:%M'), 
    data['volume'], 
    color='#FF1C1C', 
    edgecolor='black', 
    linewidth=1.5, 
    alpha=0.9, 
    zorder=3
)

ax.set_facecolor(CHART_BG_COLOR)
fig.patch.set_facecolor(CHART_BG_COLOR)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color(TEXT_COLOR)
ax.spines['bottom'].set_color(TEXT_COLOR)
ax.tick_params(colors=TEXT_COLOR, labelsize=11)
ax.set_title("DDoS Attack Traffic Volume (Last 1 Hour)", fontsize=18, color=TEXT_COLOR, weight='bold', pad=20)
ax.set_xlabel("Time (HH:MM)", fontsize=12, color=TEXT_COLOR)
ax.set_ylabel("Attack Volume", fontsize=12, color=TEXT_COLOR)
ax.set_ylim(0, max(data['volume']) + 30)
ax.grid(visible=False)

for bar in bars:
    height = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, height + 1, f'{int(height)}', 
            ha='center', va='bottom', color='white', fontsize=10, weight='bold')

st.pyplot(fig)

# ------------------ 위치 API 테스트 ------------------
st.markdown("### 테스트용 위치 확인 (8.8.8.8)")
test_ip = "8.8.8.8"
try:
    res = requests.get(f"http://ip-api.com/json/{test_ip}").json()
    if res["status"] == "success":
        st.success(f"위치 확인 성공: {res['lat']}, {res['lon']} ({res['city']}, {res['country']})")
    else:
        st.warning("위치 조회 실패: 응답 상태 오류")
except Exception as e:
    st.error(f"요청 중 오류 발생: {e}")

# ------------------ 위험도 로그 및 지도 ------------------
df_dummy = pd.DataFrame({
    'timestamp': pd.date_range(start=now - timedelta(minutes=50), periods=5, freq='10min'),
    'src_ip': [generate_random_public_ip() for _ in range(5)],
    'dst_ip': ['192.168.0.10', '10.0.0.2', '8.8.4.4', '172.16.0.5', '1.1.1.2'],
    'label': ['Normal', 'Attack', 'Attack', 'Normal', 'Attack'],
    '위험도': np.round(np.random.rand(5), 2)
})

# ------------------ 위험도 기반 이메일 알림 ------------------
for _, row in df_dummy.iterrows():
    if row['위험도'] >= 0.8:
        subject = "[경고] DDoS 공격 탐지됨"
        body = f"""
공격 IP: {row['src_ip']}
목표 IP: {row['dst_ip']}
위험도: {row['위험도']}
시간: {row['timestamp']}
"""
        send_email_alert("i01091624393@gmail.com", subject, body)

st.markdown("### 🔥 위험도 상위 5개 로그")
st.dataframe(df_dummy)
st.download_button("📥 위험도 CSV 다운로드", df_dummy.to_csv(index=False), file_name="top5_risk_logs.csv", mime="text/csv")

st.markdown("### 🗺️ 공격 출발지 위치 지도")

@st.cache_data(ttl=600)
def get_or_create_location(ip):
    try:
        conn = sqlite3.connect("logs.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS ip_location (ip TEXT PRIMARY KEY, lat REAL, lon REAL)''')
        conn.commit()
        c.execute("SELECT lat, lon FROM ip_location WHERE ip=?", (ip,))
        row = c.fetchone()
        if row:
            return row
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res["status"] == "success":
            lat, lon = res["lat"], res["lon"]
            c.execute("INSERT INTO ip_location (ip, lat, lon) VALUES (?, ?, ?)", (ip, lat, lon))
            conn.commit()
            return lat, lon
    except:
        return None
    finally:
        conn.close()

locations = []
for ip in df_dummy['src_ip']:
    loc = get_or_create_location(ip)
    if loc:
        lat, lon = loc
        locations.append({"lat": lat, "lon": lon, "ip": ip})

map_data = pd.DataFrame(locations)

if not map_data.empty:
    st.write("📌 지도 데이터:", map_data)
    st.pydeck_chart(pdk.Deck(
        map_style='mapbox://styles/mapbox/dark-v10',
        initial_view_state=pdk.ViewState(latitude=36.5, longitude=127.5, zoom=3.5, pitch=40),
        layers=[pdk.Layer(
            'ScatterplotLayer',
            data=map_data,
            get_position='[lon, lat]',
            get_color='[255, 100, 100, 160]',
            get_radius=40000,
            pickable=True
        )]
    ))
else:
    st.warning("❌ 위치 데이터를 찾을 수 없습니다.")

st.markdown(f"""
<hr style="border:1px solid {PRIMARY_COLOR}; margin-top: 40px;">
<p style="text-align:center; color:{TEXT_COLOR}; font-size:12px; margin-bottom:0;">
© 2025 DDoS Detection Dashboard · Powered by Streamlit
</p>
""", unsafe_allow_html=True)
