# routers/report.py – PDF 리포트 다운로드 API

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from database import get_db, Log
from fpdf import FPDF
import os
from datetime import datetime

router = APIRouter()

@router.get("/pdf")
def generate_pdf_report(db: Session = Depends(get_db)):
    logs = db.query(Log).order_by(Log.timestamp.desc()).limit(30).all()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="DDoS 탐지 리포트 (최근 30건)", ln=True, align="C")
    pdf.ln(10)

    for log in logs:
        line = f"[{log.timestamp}] {log.src_ip} ▶ {log.attack_type or 'BENIGN'} (위험도: {log.risk_score:.2f})"
        pdf.cell(200, 10, txt=line, ln=True)

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join("reports", filename)
    os.makedirs("reports", exist_ok=True)
    pdf.output(filepath)

    return FileResponse(path=filepath, filename=filename, media_type='application/pdf')
