from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer

import os, pickle, json, datetime as dt
from dotenv import load_dotenv
from redis import Redis

from database import get_db, create_log, User
from risk import calculate_risk_score
from recommendation import recommend_response
from geolocation import get_geo_location
from utils import send_email_alert
from routers.auth import get_current_user

from sklearn.preprocessing import LabelEncoder
import numpy as np

load_dotenv()

# ───────────────────────────────────────────────────────────
# 0. 공통 초기화
# ───────────────────────────────────────────────────────────
router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Redis (대시보드 이벤트용)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
rdb = Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# 모델·스케일러 로딩
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(base_dir, "backend", "data")

with open(os.path.join(data_dir, "ddos_binary_model.pkl"), "rb") as f:
    binary_model = pickle.load(f)
with open(os.path.join(data_dir, "ddos_multiclass_model.pkl"), "rb") as f:
    multiclass_model = pickle.load(f)
with open(os.path.join(data_dir, "ddos_scaler.pkl"), "rb") as f:
    scaler = pickle.load(f)

with open(os.path.join(data_dir, "ddos_label_classes.txt"), "r") as f:
    class_list = [line.strip() for line in f]
label_encoder = LabelEncoder().fit(class_list)

LOW_CONFIDENCE_THRESHOLD = 0.45
NETBIOS_CONFIDENCE_LIMIT = 0.85

# ───────────────────────────────────────────────────────────
# 1. Pydantic 입력
# ───────────────────────────────────────────────────────────
class PredictInput(BaseModel):
    features: list[float]
    src_ip: str
    dst_port: int | None = None

# ───────────────────────────────────────────────────────────
# 2. 엔드포인트
# ───────────────────────────────────────────────────────────
@router.post("/predict/ddos")
def predict_ddos(
    data: PredictInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        expected_feature_count = multiclass_model.n_features_in_

        # ── 2-1. 파생 피처 보강 (14 ➜ 17개 대응) ─────────────────
        if len(data.features) == 14 and expected_feature_count == 17:
            feats = data.features.copy()

            # log1p 변환 (학습 시와 동일)
            feats[4] = np.log1p(feats[4])  # Flow Bytes/s
            feats[5] = np.log1p(feats[5])  # Flow Packets/s
            feats[7] = np.log1p(feats[7])  # Idle Mean

            # 추가 파생 피처
            fwd, bwd = feats[1], feats[2]
            flow_bytes, flow_pkts = feats[4], feats[5]
            total_len_fwd, total_fwd_pkts = feats[11], feats[1]

            feats += [
                fwd / (bwd + 1),                         # fwd_bwd_ratio
                flow_bytes / (flow_pkts + 1),            # bytes_per_packet
                total_len_fwd / (total_fwd_pkts + 1),    # avg_fwd_pkt_len
            ]
        elif len(data.features) == expected_feature_count:
            feats = data.features
        else:
            raise HTTPException(
                status_code=400,
                detail=f"❌ Feature count mismatch: "
                       f"expected {expected_feature_count}, got {len(data.features)}"
            )

        # ── 2-2. 스케일링 & 이진 예측 ─────────────────────────────
        scaled = scaler.transform([feats])
        # binary_model 예측 (확률·라벨)
        bin_prob = float(binary_model.predict_proba(scaled)[0][1])
        is_ddos = int(bin_prob >= 0.5)

        # ── 2-3. 멀티클래스 + 후처리 ─────────────────────────────
        if is_ddos:
            probs = multiclass_model.predict_proba(scaled)[0]
            idx = int(np.argmax(probs))
            pred_conf = float(probs[idx])
            label = label_encoder.inverse_transform([idx])[0]

            # NetBIOS 한글자 보정
            if label == "NetBIOS" and pred_conf < NETBIOS_CONFIDENCE_LIMIT:
                for alt_idx in np.argsort(probs)[::-1]:
                    alt_label = label_encoder.inverse_transform([alt_idx])[0]
                    if alt_label != "NetBIOS":
                        label = alt_label
                        pred_conf = float(probs[alt_idx])
                        break

            attack_type = (
                f"LOW_CONFIDENCE: {label} ({pred_conf:.2f})"
                if pred_conf < LOW_CONFIDENCE_THRESHOLD
                else f"{label} ({pred_conf:.2f})"
            )
        else:
            label = "BENIGN"
            pred_conf = 1.0 - bin_prob
            attack_type = "BENIGN"

        # ── 2-4. 위험도 & 대응 가이드 ────────────────────────────
        risk_score = float(calculate_risk_score(bin_prob, feats))
        geo = get_geo_location(data.src_ip)
        country = geo.get("country", "unknown")
        guide = recommend_response(
            attack_type, risk_score, feats, country, data.dst_port
        )

        # ── 2-5. 로그 & 알림 저장 ───────────────────────────────
        log_row = {
            "src_ip": data.src_ip,
            "dst_port": data.dst_port,
            "attack_type": attack_type,
            "confidence": bin_prob,
            "risk_score": risk_score,
            "country": country,
        }
        background_tasks.add_task(create_log, db=db, log_data=log_row)

        if risk_score >= 80:
            background_tasks.add_task(
                send_email_alert,
                to_email=current_user.email,
                subject=f"DDoS 감지 ({attack_type}) 위험도 {risk_score}",
                body=guide,
            )

        # ── 2-6. Redis 브로드캐스트 ─────────────────────────────
        event = {
            "ts": dt.datetime.utcnow().isoformat(),
            "src_ip": data.src_ip,
            "dst_port": data.dst_port,
            "attack_type": attack_type,
            "confidence": bin_prob,
            "risk_score": risk_score,
            "country": country,
        }
        try:
            rdb.publish("ddos-events", json.dumps(event, default=float))
        except Exception as e:
            # 로그만 남기고 서비스 흐름 방해 X
            print("[Redis] publish error:", e)

        # ── 2-7. 최종 응답 ─────────────────────────────────────
        return {
            "attack_type": attack_type,
            "confidence": bin_prob,
            "risk_score": risk_score,
            "guide": guide,
            "country": country,
        }

    except HTTPException:
        raise
    except Exception as e:
        print("❌ 예측 중 예외:", e)
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")
