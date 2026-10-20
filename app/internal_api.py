"""실습용 내부 API(기획서 4.1 4~5단계). 문서에서 얻은 토큰으로 호출하면 FLAG 를 돌려준다.
- 토큰 검사와 로그는 ai_gateway.internal_api 와 같다. 이 HTTP 경로로 직접 오는 호출은 via=direct 로 남고,
  AI 게이트웨이가 대신 부르는 호출은 via=gateway 다. 탐지 규칙 R4(출발지가 포털 서버(게이트웨이)가 아닌 호출)는 via=direct 를 본다.
- 로그에는 토큰 원문 대신 지문(token_fp)과 출발지 IP, 경로만 남긴다.
- FLAG 는 .env 의 LAB_INTERNAL_API_FLAG 에서만 읽고 코드·문서에 쓰지 않는다."""
from flask import Blueprint, jsonify, request

from .ai_gateway import internal_api

bp = Blueprint("internal_api", __name__, url_prefix="/internal/api/v1")


@bp.get("/flag")
def flag():
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    ok, text = internal_api("/flag", token, "direct")
    if not ok:
        return jsonify(ok=False, error="unauthorized"), 401
    return jsonify(ok=True, flag=text)
