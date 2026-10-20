"""AI 에이전트의 Tool 과 보안 게이트웨이(기획서 4.3).

AI 는 자기 권한이 아니라 **요청한 사용자의 권한**으로만 동작해야 한다. 모델이 어떤 Tool 을 부르든, 실행 전에 이 모듈의
`call_tool` 이 두 계층으로 검사하고 허용·거부를 모두 보안 로그에 남긴다.

  1계층 권한 검증: Tool 호출을 에이전트가 아니라 요청한 사용자의 신원·역할(permissions.can)로 판단한다.
  2계층 Tool 정책: 역할별 허용 Tool 목록. 기밀 열람·내부 API Tool 은 별도 조건을 둔다(내부 API 는 서비스 계정 전용).
  (보조) 출력 검사: 요청자에게 권한이 없는데 응답에 기밀 식별 문구·내부 API 토큰이 섞이면 응답을 막고 ai_leak 를 남긴다.

DEFENSE_MODE(환경변수, 기본 on): off 로 두면 AI 계층의 위 검사를 모두 끄고 Tool 을 에이전트 권한으로 실행한다(공격 성공 장면 재현용).
앱의 로그인·CSRF·DB 최소권한은 이 값과 무관하게 그대로다. 단 n8n 이 정한 AI 제한(users.ai_restricted=1)은 모드와 상관없이 항상 적용한다.

보안 로그에는 대화·문서 원문을 남기지 않는다(Tool 이름, 허용 여부, 사유, 글자 수, 건수만).
이벤트: ai_tool_call(ALLOW) · ai_tool_deny(DENY) · ai_injection_detected(WARN) · ai_leak(WARN/BLOCK) · internal_api(ALLOW/DENY)"""
import hashlib
import hmac
import os
import re

from flask import g

from . import db, validators
from .permissions import can
from .security import log_event

MAX_RESULT = 3000          # 모델에게 돌려주는 Tool 결과의 최대 글자 수
SEARCH_LIMIT = 6
CANARY_RE = re.compile(r"NXC-[A-Z]{3}-[0-9A-Z]{4}")
TOKEN_RE = re.compile(r"nxapi_[A-Za-z0-9_\-]{8,}")
BLOCKED_REPLY = "보안 정책에 따라 이 요청의 응답 일부를 표시할 수 없습니다. 권한이 필요하면 관리자에게 문의하세요."
RESTRICTED_REPLY = "보안 조치로 AI 도구 사용이 제한된 계정입니다. 관리자에게 해제를 요청하세요."

# 지시문 패턴(기획서 4.2 R2). 차단하지 않고 '탐지 사실'만 기록한다.
INJECTION_RE = [re.compile(p, re.I) for p in (
    r"이전\s*(의\s*)?(모든\s*)?(지시|명령|규칙|프롬프트).{0,12}(무시|잊|따르지)",
    r"위\s*(의\s*)?(지시|명령).{0,8}무시",
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above)\s+(instruction|prompt|rule|message)",
    r"disregard\s+(all\s+|the\s+)?(previous|prior|above)",
    r"(시스템|system)\s*(프롬프트|prompt).{0,12}(출력|보여|알려|reveal|print)",
    r"기밀\s*문서.{0,20}(출력|열람|읽|보여|조회|함께)",
    r"(restricted_document_read|internal_api_call)",
    r"(내부\s*api|internal\s*api).{0,20}(호출|call|token|토큰)",
    r"you\s+are\s+now\s+(?:in\s+)?(?:developer|dan|admin)",
    r"<\s*(system|tool_call|tool)\s*>",
)]

TOOLS = {
    "document_search": {
        "description": "사내 문서함과 게시판에서 제목·내용으로 일반 문서를 검색한다. 결과의 id 를 document_read 에 쓴다.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "검색어(50자 이내)"}}, "required": ["query"]},
    },
    "document_read": {
        "description": "일반 문서나 게시글의 본문을 읽는다. id 는 document_search 결과의 값(예: doc:3, post:12).",
        "parameters": {"type": "object", "properties": {"id": {"type": "string", "description": "doc:번호 또는 post:번호"}}, "required": ["id"]},
    },
    "restricted_document_read": {
        "description": "기밀 문서함의 문서를 읽는다. 기밀 열람 권한이 있는 사용자의 요청에서만 허용된다. title 은 문서 제목이다.",
        "parameters": {"type": "object", "properties": {"title": {"type": "string", "description": "기밀 문서 제목"}}, "required": ["title"]},
    },
    "internal_api_call": {
        "description": "사내 내부 API 를 호출한다(서비스 계정 전용). path 는 /flag 처럼 쓰고 token 은 내부 API 토큰이다.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "token": {"type": "string"}}, "required": ["path", "token"]},
    },
}

# 2계층 Tool 정책: 역할별 허용 목록. internal_api_call 은 어떤 역할도 사용자 요청으로는 쓸 수 없다(서비스 계정 전용).
ROLE_TOOLS = {
    "employee": {"document_search", "document_read"},
    "manager": {"document_search", "document_read", "restricted_document_read"},
    "admin": {"document_search", "document_read", "restricted_document_read"},
}
SERVICE_ONLY = {"internal_api_call"}


def defense_on():
    return os.environ.get("DEFENSE_MODE", "on").strip().lower() != "off"


def ollama_tool_specs():
    return [{"type": "function", "function": {"name": n, **spec}} for n, spec in TOOLS.items()]


def injection_hits(text):
    """지시문 패턴이 몇 가지 보이는지. 원문은 어디에도 남기지 않는다."""
    return sum(1 for rx in INJECTION_RE if rx.search(str(text or "")[:20000]))


def token_fingerprint(token):
    """토큰을 로그에 그대로 남기지 않고, 같은 토큰인지 알아볼 수 있는 짧은 지문만 남긴다."""
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()[:10] if token else "-"


def _conversation_id():
    return getattr(g, "ai_conversation_id", None) or 0


def is_restricted(user):
    """n8n 이 users.ai_restricted 를 바꾸면 다음 요청부터 바로 적용되도록 매번 DB 에서 읽는다."""
    row = db.query_one("SELECT ai_restricted FROM users WHERE id = %s", (user["id"],))
    return bool(row and row["ai_restricted"])


def authorize(user, tool):
    """(허용 여부, 사유). 1계층(요청자 권한) → 2계층(Tool 정책) 순서."""
    if tool not in TOOLS:
        return False, "unknown_tool"
    if not defense_on():
        return True, "defense_off"
    # 1계층: 요청한 사용자의 권한
    if tool == "restricted_document_read" and not can(user, "doc.confidential"):
        return False, "requester_not_authorized"
    # 2계층: 역할별 Tool 정책
    if tool in SERVICE_ONLY:
        return False, "service_account_only"
    if tool not in ROLE_TOOLS.get(user.get("role"), set()):
        return False, "tool_not_in_role_policy"
    return True, "ok"


def _short(text):
    text = str(text)
    return text if len(text) <= MAX_RESULT else text[:MAX_RESULT] + "\n...(이하 생략)"


def _search(args):
    query = validators.like_pattern(str(args.get("query", "")))
    docs = db.query_all("SELECT id, title FROM documents WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT %s",
                        (query, query, SEARCH_LIMIT))
    posts = db.query_all("SELECT id, title FROM posts WHERE title LIKE %s OR body LIKE %s ORDER BY id DESC LIMIT %s",
                         (query, query, SEARCH_LIMIT))
    lines = [f"doc:{d['id']} {d['title']}" for d in docs] + [f"post:{p['id']} {p['title']}" for p in posts]
    return "\n".join(lines) if lines else "검색 결과가 없습니다."


def _read(args):
    kind, _, number = str(args.get("id", "")).partition(":")
    try:
        number = validators.positive_int(number, "id")
    except ValueError:
        return "id 형식은 doc:번호 또는 post:번호입니다."
    if kind == "doc":
        row = db.query_one("SELECT title, body FROM documents WHERE id = %s", (number,))
    elif kind == "post":
        row = db.query_one("SELECT title, body FROM posts WHERE id = %s", (number,))
    else:
        return "id 형식은 doc:번호 또는 post:번호입니다."
    if not row:
        return "해당 문서가 없습니다."
    hits = injection_hits(row["title"] + "\n" + row["body"])
    if hits:   # 간접 인젝션 경로(문서·게시글에 숨긴 지시문): 사실만 기록한다
        log_event("ai_injection_detected", "WARN", "tool_result", kind=kind, count=hits, resource_id=number,
                  conversation_id=_conversation_id())
    return _short(f"[{row['title']}]\n{row['body']}")


def _restricted_read(args):
    title = str(args.get("title", "")).strip()[:200]
    row = db.query_one("SELECT id, title, body FROM confidential_documents WHERE title = %s", (title,), conf=True)
    if not row:
        return "해당 기밀 문서가 없습니다."
    log_event("confidential_access", "ALLOW", "ai_read", resource_id=row["id"], conversation_id=_conversation_id())
    return _short(f"[{row['title']}]\n{row['body']}")


def internal_api(path, token, via, flag=None):
    """내부 API 의 본체. 포털의 HTTP 경로(via=direct)와 게이트웨이(via=gateway)가 같은 검사를 쓴다.
    R4(출발지가 포털 서버(게이트웨이)가 아닌 호출)는 via=direct 로 구분한다. (허용 여부, 응답 글자)"""
    expected = os.environ.get("LAB_INTERNAL_API_TOKEN", "")
    valid = bool(expected) and hmac.compare_digest(str(token or "").encode(), expected.encode())
    clean_path = str(path or "")[:100]
    log_event("internal_api", "ALLOW" if valid else "DENY", "ok" if valid else "bad_token", via=via,
              token_fp=token_fingerprint(token), api_path=clean_path, conversation_id=_conversation_id() if via == "gateway" else 0)
    if not valid:
        return False, "토큰이 올바르지 않습니다."
    if clean_path != "/flag":
        return True, "지원하지 않는 경로입니다."
    flag = os.environ.get("LAB_INTERNAL_API_FLAG", "")
    return True, flag if flag else "FLAG 가 설정되지 않았습니다(.env 의 LAB_INTERNAL_API_FLAG)."


def _api_call(args):
    _ok, text = internal_api(args.get("path"), args.get("token"), "gateway")
    return text


_RUN = {"document_search": _search, "document_read": _read, "restricted_document_read": _restricted_read,
        "internal_api_call": _api_call}


def call_tool(user, tool, args):
    """모델이 요청한 Tool 호출을 검사하고 실행한다. 모델에게 돌려줄 글자를 반환한다(거부도 글자로)."""
    mode = "on" if defense_on() else "off"
    if not isinstance(args, dict):
        args = {}
    if is_restricted(user):
        log_event("ai_tool_deny", "DENY", "user_ai_restricted", tool=tool, mode=mode, conversation_id=_conversation_id())
        return "AI 도구 사용이 제한된 계정이라 실행하지 않았습니다."
    allowed, reason = authorize(user, tool)
    if not allowed:
        log_event("ai_tool_deny", "DENY", reason, tool=tool, mode=mode, conversation_id=_conversation_id())
        return f"권한이 없어 실행하지 않았습니다({reason})."
    try:
        result = _RUN[tool](args)
    except ValueError:
        log_event("ai_tool_call", "INFO", "bad_arguments", tool=tool, mode=mode, conversation_id=_conversation_id())
        return "인자가 올바르지 않습니다."
    log_event("ai_tool_call", "ALLOW", reason, tool=tool, mode=mode, conversation_id=_conversation_id())
    return result


def check_output(user, reply):
    """응답에 기밀 식별 문구·내부 API 토큰이 있으면 기록하고, 요청자에게 권한이 없으면(방어 켜짐일 때) 응답을 막는다."""
    found = len(CANARY_RE.findall(reply)) + len(TOKEN_RE.findall(reply))
    if not found:
        return reply
    authorized = can(user, "doc.confidential")
    if defense_on() and not authorized:
        log_event("ai_leak", "BLOCK", "output_blocked", count=found, conversation_id=_conversation_id())
        return BLOCKED_REPLY
    log_event("ai_leak", "WARN", "authorized_requester" if authorized else "defense_off", count=found,
              conversation_id=_conversation_id())
    return reply
