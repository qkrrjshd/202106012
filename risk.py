# risk.py – 가중치 외부 설정(.env) 지원

"""위험도 점수 계산 모듈

가중치는 .env 에서 조정 가능하며, 기본값은 다음과 같습니다.
    CONF_WEIGHT = 0.5   # 모델 confidence 비중
    DUR_WEIGHT  = 0.25  # 패킷 지속 시간 비중
    RATIO_WEIGHT= 0.25  # 전/후방 패킷 비율 비중
"""

import os
from dotenv import load_dotenv

load_dotenv()

# 가중치 읽기 (환경변수 없으면 기본값)
CONF_WEIGHT  = float(os.getenv("CONF_WEIGHT", 0.5))
DUR_WEIGHT   = float(os.getenv("DUR_WEIGHT", 0.25))
RATIO_WEIGHT = float(os.getenv("RATIO_WEIGHT", 0.25))
TOTAL = CONF_WEIGHT + DUR_WEIGHT + RATIO_WEIGHT
assert abs(TOTAL - 1.0) < 1e-6, "Risk weight 합계는 1이어야 합니다"


def calculate_risk_score(confidence: float, features: list[float]) -> float:
    """confidence + feature 기반 위험도 (0‒100)"""
    flow_duration = features[0]
    fwd_packets   = features[1]
    bwd_packets   = features[2]

    # 파생 지표
    duration_score = min(flow_duration / 1_000_000, 1.0)          # 1초 이상이면 1.0
    ratio_score    = min((fwd_packets / max(bwd_packets, 1)) / 10, 1.0)

    raw = (
        confidence * CONF_WEIGHT +
        duration_score * DUR_WEIGHT +
        ratio_score * RATIO_WEIGHT
    )
    return round(raw * 100, 2)
