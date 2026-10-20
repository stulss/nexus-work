"""AI 어시스턴트 채팅방(GPT 식 여러 대화) 화면·엔드포인트.
응답을 만드는 AI 는 `app.config["CHAT_RESPONDER"]` 로 갈아 끼운다(실제 연결은 ai_agent.py, 환경변수 AI_MODE).

접점(Responder): `responder(user: dict, message: str, history: list[dict]) -> str`
- `user` 는 지금 로그인한 사용자(id, username, role, dept, display_name)다. 챗봇이 하는 모든 조회는 이 사용자의 권한을 넘을 수 없다.
  (권한 검사는 ai_gateway. 앱은 항상 현재 로그인 사용자만 넘기고, 폼으로 사용자를 바꿀 수 없다.)
- `history` 는 **이 대화방의 본인** 최근 대화(오래된 것부터, 이번 메시지는 제외)다: [{"sender": "user"|"assistant", "content": str}, ...]
- 반환값은 일반 글자로만 취급한다(HTML 로 해석하지 않고, 제어문자 제거·길이 제한). 예외가 나도 앱은 안전한 안내 문구를 남긴다.
- 응답이 오래 걸리면 호출 쪽 요청이 그동안 묶인다. 실제 구현은 자체 시간 제한을 둔다.

대화방: 사용자마다 여러 개. 본인 대화방만 열 수 있고 남의 번호는 404(authz_deny 기록). 제목은 첫 질문에서 따온다.
앱이 지키는 것: 로그인 필요, CSRF, 입력 길이·문자 검증, 사용자당 속도 제한, 대화 기록은 본인 것만 조회·표시, 응답도 이스케이프.
대화 내용은 DB(chat_messages)에만 저장하고 보안 로그에는 글자 수만 남긴다."""
from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, url_for

from . import db, validators
from .auth import login_required
from .security import ip_rate_limited, log_event

bp = Blueprint("chat", __name__)

MAX_MESSAGE = 2000
MAX_REPLY = 8000
HISTORY_SHOWN = 50
HISTORY_FOR_RESPONDER = 10
CONVERSATIONS_SHOWN = 40
TITLE_LEN = 30
FALLBACK_REPLY = "답변을 만들지 못했습니다. 잠시 후 다시 시도하세요."
MESSAGE_ERROR = f"메시지는 1~{MAX_MESSAGE:,}자로 입력하세요(제어문자 사용 불가)."
RATE_ERROR = "메시지를 너무 빠르게 보내고 있습니다. 잠시 후 다시 시도하세요."


def placeholder_responder(user, message, history):
    """실제 AI 연결 전의 시험 응답. 받은 내용을 그대로 돌려준다(화면에서는 이스케이프되어 표시된다)."""
    return f"[시험 응답] {user['display_name']}님의 메시지를 받았습니다.\n{message}"


def _clean_reply(value):
    text = validators.CONTROL_RE.sub("", str(value)).strip()
    return text[:MAX_REPLY] or "(빈 응답)"


def _conversations(user_id):
    return db.query_all("SELECT id, title, updated_at FROM chat_conversations WHERE user_id = %s "
                        "ORDER BY updated_at DESC, id DESC LIMIT %s", (user_id, CONVERSATIONS_SHOWN))


def _own_conversation(user_id, conversation_id):
    return db.query_one("SELECT id, title FROM chat_conversations WHERE id = %s AND user_id = %s", (conversation_id, user_id))


def _history(conversation_id, limit):
    rows = db.query_all("SELECT id, sender, content, created_at FROM chat_messages WHERE conversation_id = %s "
                        "ORDER BY id DESC LIMIT %s", (conversation_id, limit))
    return list(reversed(rows))


def _latest_conversation_id(user_id):
    row = db.query_one("SELECT id FROM chat_conversations WHERE user_id = %s ORDER BY updated_at DESC, id DESC LIMIT 1", (user_id,))
    return row["id"] if row else None


def _conversation_id_arg(raw):
    try:
        return validators.positive_int(raw, "conversation_id")
    except ValueError:
        abort(404)


def _title_from(message):
    line = " ".join(message.split())
    return (line[:TITLE_LEN] + "…") if len(line) > TITLE_LEN else line


def _render(conversation_id=None, error=None, status=200):
    user_id = g.user["id"]
    current = _own_conversation(user_id, conversation_id) if conversation_id else None
    return render_template("chat.html", messages=_history(current["id"], HISTORY_SHOWN) if current else [],
                           conversations=_conversations(user_id), current=current, error=error,
                           placeholder=current_app.config["CHAT_RESPONDER"] is placeholder_responder,
                           ai_mode=current_app.config.get("AI_MODE", "placeholder"),
                           max_message=MAX_MESSAGE, limit=current_app.config["CHAT_USER_LIMIT"]), status


def _send(user, conversation_id, message_raw):
    """한 번의 질문을 처리한다. (HTTP 상태, 내용 dict). 내용: ok, error 또는 conversation_id·title·reply·time."""
    if ip_rate_limited(f"chat:{user['id']}", current_app.config["CHAT_USER_LIMIT"]):
        log_event("rate_limited", "BLOCK", "chat_user_limit")
        return 429, {"ok": False, "error": RATE_ERROR, "conversation_id": conversation_id}
    try:
        message = validators.text(message_raw, "message", 1, MAX_MESSAGE, multiline=True)
    except ValueError as exc:
        log_event("input_rejected", "DENY", str(exc), field="chat")
        return 400, {"ok": False, "error": MESSAGE_ERROR, "conversation_id": conversation_id}

    if conversation_id is None:
        title = _title_from(message)
        conversation_id = db.execute("INSERT INTO chat_conversations(user_id, title) VALUES(%s, %s)", (user["id"], title))
    else:
        title = None
    history = [{"sender": r["sender"], "content": r["content"]} for r in _history(conversation_id, HISTORY_FOR_RESPONDER)]
    # 사용자 메시지는 응답을 기다리기 전에 먼저 확정한다(응답 생성이 실패·지연되어도 기록은 남는다).
    db.execute("INSERT INTO chat_messages(user_id, conversation_id, sender, content) VALUES(%s, %s, 'user', %s)",
               (user["id"], conversation_id, message))
    db.commit()
    log_event("chat_message", "INFO", "ok", chars=len(message), conversation_id=conversation_id)

    g.ai_conversation_id = conversation_id            # 에이전트가 같은 대화방 번호로 Tool 로그를 남긴다
    try:
        reply = _clean_reply(current_app.config["CHAT_RESPONDER"](dict(user), message, history))
    except Exception as exc:  # 응답기가 무엇을 던져도 사용자에게 내부 정보를 보이지 않는다
        log_event("chat_responder_error", "ERROR", type(exc).__name__)
        reply = FALLBACK_REPLY
    db.execute("INSERT INTO chat_messages(user_id, conversation_id, sender, content) VALUES(%s, %s, 'assistant', %s)",
               (user["id"], conversation_id, reply))
    db.execute("UPDATE chat_conversations SET updated_at = NOW() WHERE id = %s", (conversation_id,))
    log_event("chat_reply", "INFO", "ok", chars=len(reply), conversation_id=conversation_id)
    if title is None:
        row = _own_conversation(user["id"], conversation_id)
        title = row["title"] if row else ""
    return 200, {"ok": True, "conversation_id": conversation_id, "title": title, "reply": reply}


def _wants_json():
    return request.headers.get("X-Requested-With") == "fetch" or request.accept_mimetypes.best == "application/json"


@bp.get("/chat")
@login_required
def chat_view():
    """가장 최근 대화방을 연다. 대화방이 없으면 새 대화 화면."""
    return _render(_latest_conversation_id(g.user["id"]))


@bp.get("/chat/new")
@login_required
def chat_new():
    return _render(None)


@bp.get("/chat/c/<int:conversation_id>")
@login_required
def chat_open(conversation_id):
    if not _own_conversation(g.user["id"], conversation_id):
        log_event("authz_deny", "DENY", "conversation_not_owned", resource_id=conversation_id)
        abort(404)
    return _render(conversation_id)


@bp.post("/chat/send")
@login_required
def chat_send_message():
    """화면의 보내기. conversation_id 가 없으면 새 대화방을 만든다. fetch(JSON) 와 일반 폼 둘 다 받는다."""
    raw_id = request.form.get("conversation_id", "")
    conversation_id = None
    if raw_id:
        conversation_id = _conversation_id_arg(raw_id)
        if not _own_conversation(g.user["id"], conversation_id):
            log_event("authz_deny", "DENY", "conversation_not_owned", resource_id=conversation_id)
            if _wants_json():
                return jsonify(ok=False, error="대화방을 찾을 수 없습니다."), 404
            abort(404)
    status, payload = _send(g.user, conversation_id, request.form.get("message", ""))
    if _wants_json():
        return jsonify(payload), status
    if status != 200:
        return _render(payload.get("conversation_id"), payload["error"], status)
    return redirect(url_for("chat.chat_open", conversation_id=payload["conversation_id"]), 303)


@bp.post("/chat/messages")
@login_required
def chat_send():
    """이전 주소(호환). 가장 최근 대화방에 이어 쓰고, 없으면 새로 만든다."""
    status, payload = _send(g.user, _latest_conversation_id(g.user["id"]), request.form.get("message", ""))
    if status != 200:
        return _render(payload.get("conversation_id"), payload["error"], status)
    return redirect(url_for("chat.chat_view"), 303)
