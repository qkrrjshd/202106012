# recommendation.py – 사용자 맞춤형 대응 가이드 생성

import yaml
import os

# YAML 파일 로딩 (상대 경로 기준)
with open(os.path.join("config", "recommend.yml"), "r", encoding="utf-8") as f:
    guide_config = yaml.safe_load(f)

# 위험도 점수 등급화 함수
def risk_level(score: float) -> str:
    if score >= 80:
        return "위험"
    elif score >= 50:
        return "주의"
    else:
        return "낮음"

# 사용자 맞춤형 대응 가이드 생성 함수
def recommend_response(attack_type, risk_score, features, country, dst_port) -> str:
    level = risk_level(risk_score)
    attack = attack_type or "Unknown"

    # 기본 가이드 불러오기 (없으면 기본 메시지)
    base = guide_config.get(attack, {}).get("guide", "공격 유형에 대한 정보가 없습니다.")

    # 최종 사용자 맞춤 메시지 조립
    return (
        f"[{attack} 공격 탐지]\n\n"
        f"공격지 국가: {country or '알 수 없음'}\n"
        f"대상 포트: {dst_port or '알 수 없음'}\n"
        f"위험도: {risk_score:.2f}점 ({level})\n\n"
        f"{base.strip()}"
    )
