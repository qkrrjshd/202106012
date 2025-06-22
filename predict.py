from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer

import os
import pickle
from dotenv import load_dotenv

from database import get_db, create_log, User
from risk import calculate_risk_score
from recommendation import recommend_response
from geolocation import get_geo_location
from utils import send_email_alert
from routers.auth import get_current_user

from sklearn.preprocessing import LabelEncoder
import numpy as np

load_dotenv()

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ✅ 현재 경로 기반 data 경로 구성
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
data_dir = os.path.join(base_dir, "backend", "data")

binary_model_path = os.path.join(data_dir, "ddos_binary_model.pkl")
multiclass_model_path = os.path.join(data_dir, "ddos_multiclass_model.pkl")
label_class_path = os.path.join(data_dir, "ddos_label_classes.txt")
scaler_path = os.path.join(data_dir, "ddos_scaler.pkl")

# ✅ 모델 및 scaler 로딩
with open(binary_model_path, "rb") as f:
    binary_model = pickle.load(f)
with open(multiclass_model_path, "rb") as f:
    multiclass_model = pickle.load(f)
with open(scaler_path, "rb") as f:
    scaler = pickle.load(f)

# ✅ 라벨 인코더
with open(label_class_path, "r") as f:
    class_list = [line.strip() for line in f]
label_encoder = LabelEncoder()
label_encoder.fit(class_list)

# ✅ 임계값 설정
LOW_CONFIDENCE_THRESHOLD = 0.45
NETBIOS_CONFIDENCE_LIMIT = 0.85

class PredictInput(BaseModel):
    features: list[float]
    src_ip: str
    dst_port: int | None = None

@router.post("/predict/ddos")
def predict_ddos(
    data: PredictInput,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        print("[입력 features]:", data.features)
        expected_feature_count = multiclass_model.n_features_in_

        # ✅ 파생 피처 생성
        if len(data.features) == 14 and expected_feature_count == 17:
            features = data.features.copy()

            # ✅ log1p 변환 적용 (학습 시와 동일하게)
            features[4] = np.log1p(features[4])  # Flow Bytes/s
            features[5] = np.log1p(features[5])  # Flow Packets/s
            features[7] = np.log1p(features[7])  # Idle Mean

            # ✅ 파생 피처
            fwd = features[1]
            bwd = features[2]
            flow_bytes = features[4]
            flow_pkts = features[5]
            total_len_fwd = features[11]
            total_fwd_pkts = features[1]

            fwd_bwd_ratio = fwd / (bwd + 1)
            bytes_per_packet = flow_bytes / (flow_pkts + 1)
            avg_fwd_pkt_len = total_len_fwd / (total_fwd_pkts + 1)

            full_features = features + [fwd_bwd_ratio, bytes_per_packet, avg_fwd_pkt_len]
            print("[✅ 파생 피처 + 로그 변환 완료]")
        elif len(data.features) == expected_feature_count:
            full_features = data.features
        else:
            raise HTTPException(status_code=400, detail=f"❌ Feature count mismatch: expected {expected_feature_count}, got {len(data.features)}")

        # ✅ 정규화
        scaled_input = scaler.transform([full_features])

        # ✅ 이진 분류 결과 (테스트용 강제 DDoS)
        confidence = 0.999
        is_ddos = 1
        print(f"[Binary] is_ddos: {is_ddos} , confidence: {confidence:.4f}")

        if is_ddos == 1:
            pred_probs = multiclass_model.predict_proba(scaled_input)[0]
            pred_class = int(np.argmax(pred_probs))
            pred_confidence = float(pred_probs[pred_class])
            label = label_encoder.inverse_transform([pred_class])[0]

            print("[Multiclass] pred_class (index):", pred_class)
            for idx, prob in enumerate(pred_probs):
                print(f"→ {label_encoder.classes_[idx]}: {prob:.4f}")

            # ✅ NetBIOS 보정
            if label == "NetBIOS" and pred_confidence < NETBIOS_CONFIDENCE_LIMIT:
                sorted_indices = np.argsort(pred_probs)[::-1]
                for idx in sorted_indices:
                    alt_label = label_encoder.inverse_transform([idx])[0]
                    if alt_label != "NetBIOS":
                        label = alt_label
                        pred_confidence = float(pred_probs[idx])
                        break

            # ✅ 라벨 출력 형식
            if pred_confidence < LOW_CONFIDENCE_THRESHOLD:
                attack_type = f"LOW_CONFIDENCE: {label} ({pred_confidence:.2f})"
            else:
                attack_type = f"{label} ({pred_confidence:.2f})"
            print("[Label Decoded] attack_type:", attack_type)
        else:
            attack_type = "BENIGN"
            print("[Binary] BENIGN 트래픽으로 판단됨")

        # ✅ GeoIP
        geo_info = get_geo_location(data.src_ip)
        country = geo_info.get("country", "unknown")
        if country == "unknown":
            if data.src_ip.startswith(("192.", "10.", "172.")):
                country = "Private IP"
            elif data.src_ip.startswith(("198.51.", "203.0.113.")):
                country = "Test IP (RFC5737)"
        print("[Geo] Country:", country)

        # ✅ 대응 가이드 + 위험도
        risk_score = calculate_risk_score(confidence, data.features)
        guide = recommend_response(attack_type, risk_score, data.features, country, data.dst_port)

        # ✅ 로그 저장
        log_data = {
            "src_ip": data.src_ip,
            "dst_port": data.dst_port,
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": risk_score,
            "country": country,
        }
        background_tasks.add_task(create_log, db=db, log_data=log_data)

        # ✅ 이메일 알림
        if risk_score >= 80:
            subject = f"DDoS 감지 ({attack_type}) 위험도 {risk_score}"
            background_tasks.add_task(
                send_email_alert,
                to_email=current_user.email,
                subject=subject,
                body=guide,
            )

        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": float(risk_score),
            "guide": guide,
            "country": country,
        }

    except Exception as e:
        print("❌ 예측 중 예외 발생:", e)
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")
