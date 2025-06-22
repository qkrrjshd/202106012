# routers/stats.py – DB‑agnostic 통계 API (SQLite·Postgres 호환)

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from database import get_db, Log
from datetime import datetime, timedelta

router = APIRouter()

# ------------------------------------------------------------------
# 방언별 "분 단위" 버킷 함수
# ------------------------------------------------------------------

def _minute_bucket(db: Session):
    dialect = db.bind.dialect.name  # "sqlite", "postgresql", ...
    if dialect == "sqlite":
        return func.strftime("%Y-%m-%d %H:%M", Log.timestamp)
    elif dialect == "postgresql":
        return func.date_trunc("minute", Log.timestamp)
    else:
        # 기타 DB는 SQLite 방식으로 폴백
        return func.strftime("%Y-%m-%d %H:%M", Log.timestamp)

# ------------------------------------------------------------------
# 1) 분 단위 트래픽 건수 (최근 1시간)
# ------------------------------------------------------------------

@router.get("/stats/traffic")
def traffic_stats(db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=1)
    bucket = _minute_bucket(db)
    rows = (
        db.query(bucket.label("time"), func.count().label("count"))
        .filter(Log.timestamp >= since)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    return [{"time": str(r.time), "count": r.count} for r in rows]

# ------------------------------------------------------------------
# 2) 분 단위 평균 위험도 (최근 1시간)
# ------------------------------------------------------------------

@router.get("/stats/risk")
def risk_stats(db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=1)
    bucket = _minute_bucket(db)
    rows = (
        db.query(bucket.label("time"), func.avg(Log.risk_score).label("avg_risk"))
        .filter(Log.timestamp >= since)
        .group_by(bucket)
        .order_by(bucket)
        .all()
    )
    return [{"time": str(r.time), "avg_risk": round(r.avg_risk, 2)} for r in rows]

# ------------------------------------------------------------------
# 3) 공격 유형별 건수 전체 통계
# ------------------------------------------------------------------

@router.get("/stats/by-attack")
def attack_type_stats(db: Session = Depends(get_db)):
    rows = (
        db.query(Log.attack_type, func.count().label("count"))
        .filter(Log.attack_type.isnot(None))
        .group_by(Log.attack_type)
        .order_by(func.count().desc())
        .all()
    )
    return [{"attack_type": r.attack_type, "count": r.count} for r in rows]
