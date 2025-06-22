# routers/admin.py – 관리자 기능 (권한 부여 + 모델 리로드)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import joblib, os
from dotenv import load_dotenv

from database import get_db, User
from routers import predict      # <-- 예측 라우터 모듈 가져오기

router = APIRouter()
load_dotenv()

@router.post("/admin/promote/{user_id}")
def promote_user_to_admin(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_admin = True
    db.commit()
    return {"message": f"User {user_id} promoted to admin."}

@router.post("/admin/reload-model")
def reload_model():
    try:
        model_path = os.getenv("MODEL_PATH", "ddos_model.pkl")
        new_model = joblib.load(model_path)
        predict.model = new_model   # ✅ 예측 라우터 전역 모델 객체 갱신
        return {"message": "Model reloaded & hot‑swapped successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model reload failed: {e}")
