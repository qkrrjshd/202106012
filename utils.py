# utils.py – 이메일 발송 재시도(tenacity) + PDF 경로 통일

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from fpdf import FPDF
from dotenv import load_dotenv
from datetime import datetime
import os
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

load_dotenv()

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# ---------------------------
# 이메일 전송 (지수 백오프 재시도)
# ---------------------------

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(smtplib.SMTPException),
    reraise=True,
)
def send_email_alert(to_email: str, subject: str, body: str) -> None:
    """지수백오프‧최대 3회 재시도로 메일 전송 안정화"""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("❌ SMTP 환경변수가 설정되지 않았습니다. .env 파일을 확인하세요.")
        return

    msg = MIMEMultipart()
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"📧 이메일 전송 성공: {to_email}")
    except Exception as e:
        print(f"❌ 이메일 전송 실패: {e}")


# ---------------------------
# 로그인 알림 이메일 보고서
# ---------------------------

def send_login_report(user: str, df_logs) -> None:
    """로그인 시점 이메일 리포트 전송"""
    login_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = "[접속 알림] DDoS 대시보드 로그인 감지"

    if df_logs.empty:
        status = "🔵 현재 시스템 상태: 정상 (위험도 로그 없음)"
    else:
        max_risk = df_logs["confidence"].max()
        status = "🟡 비정상 트래픽 감지됨" if max_risk >= 0.8 else "🟢 정상 상태 유지 중"

    body = f"사용자: {user}\n로그인 시간: {login_time}\n{status}\n"
    if not df_logs.empty:
        body += "\n최근 위험 로그:\n"
        for _, row in df_logs.iterrows():
            body += f"- {row['timestamp']} | {row['src_ip']} ▶ {row['dst_ip']} | 위험도: {row['confidence']}\n"

    send_email_alert("i01091624393@gmail.com", subject, body)


# ---------------------------
# PDF 리포트 생성 (경로 reports/ 로 통일)
# ---------------------------

def generate_pdf_report(logs, filename_prefix: str = "report") -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="DDoS 탐지 리포트", ln=True, align="C")
    pdf.ln(10)

    for log in logs:
        line = (
            f"[{log.timestamp}] {log.src_ip} ▶ {log.attack_type or 'BENIGN'} "
            f"(위험도: {log.risk_score:.2f})"
        )
        pdf.cell(200, 10, txt=line, ln=True)

    os.makedirs("reports", exist_ok=True)
    filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join("reports", filename)
    pdf.output(filepath)
    return filepath
