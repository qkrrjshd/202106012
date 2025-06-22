# database.py – DB 접속·세션·모델 일체 관리

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, func
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# ----------------------------------------------------------------
# 1) 엔진 & 세션
# ----------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./logs.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ----------------------------------------------------------------
# 2) 모델 정의
# ----------------------------------------------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String)
    dst_port = Column(Integer, nullable=True)
    attack_type = Column(String, nullable=True)
    confidence = Column(Integer, nullable=True)
    risk_score = Column(Integer)
    country = Column(String, nullable=True)
    # 좌표 칼럼(선택)
    latitude = Column(String, nullable=True)
    longitude = Column(String, nullable=True)

# ----------------------------------------------------------------
# 3) 세션 의존성 함수
# ----------------------------------------------------------------
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# database.py 내에 추가
def create_log(db: Session, log_data: dict):
    log = Log(**log_data)
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


# ----------------------------------------------------------------
# 4) 최초 테이블 생성
# ----------------------------------------------------------------
Base.metadata.create_all(bind=engine)
