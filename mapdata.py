# routers/mapdata.py – 지도 시각화용 로그 데이터 제공 API

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database import get_db, Log

router = APIRouter()

@router.get("/mapdata")
def get_map_data(db: Session = Depends(get_db)):
    logs = db.query(Log).filter(Log.risk_score >= 70).order_by(Log.timestamp.desc()).limit(50).all()
    data = []
    for log in logs:
        data.append({
            "src_ip": log.src_ip,
            "country": log.country,
            "latitude": getattr(log, "latitude", None),
            "longitude": getattr(log, "longitude", None),
            "risk_score": log.risk_score,
            "attack_type": log.attack_type,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return data
