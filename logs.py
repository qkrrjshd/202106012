# routers/logs.py – 로그 조회 + 선택적 필터

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime
from typing import List, Optional

from database import get_db, Log

router = APIRouter()

@router.get("/logs", response_model=List[dict])
def get_logs(
    db: Session = Depends(get_db),
    attack_type: Optional[str] = None,
    min_risk: int = Query(0, ge=0, le=100),
    max_risk: int = Query(100, ge=0, le=100),
    start: Optional[datetime] = None,
    end:   Optional[datetime] = None,
    limit: int = Query(100, gt=0, le=500),
):
    q = db.query(Log)
    if attack_type:
        q = q.filter(Log.attack_type == attack_type)
    q = q.filter(and_(Log.risk_score >= min_risk, Log.risk_score <= max_risk))
    if start:
        q = q.filter(Log.timestamp >= start)
    if end:
        q = q.filter(Log.timestamp <= end)

    logs = q.order_by(Log.timestamp.desc()).limit(limit).all()

    return [
        {
            "timestamp": l.timestamp.isoformat(sep=' ', timespec='seconds'),
            "src_ip": l.src_ip,
            "attack_type": l.attack_type,
            "risk_score": l.risk_score,
            "country": l.country,
        } for l in logs
    ]
