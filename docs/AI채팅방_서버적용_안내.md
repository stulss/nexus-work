# AI 채팅방(에이전트) 서버 적용 안내 — 브랜치 `ai-agent`

작성: 이시헌 · 2026-10-20 · 적용: 홍주형

## 무엇이 들어갔나
- GPT 식 대화방: 사용자별 여러 대화, 본인 대화만 열람(남의 번호는 404 + `authz_deny`).
- Ollama 에이전트: 문서 검색/읽기/제한 문서 읽기/내부 API 호출 Tool. 호출은 모두 `app/ai_gateway.py` 를 거친다(1차 요청자 권한, 2차 역할 Tool 정책, 출력 검사).
- `DEFENSE_MODE=on|off`: off 면 게이트웨이 거부를 건너뛰어 공격 성공 시나리오를 재현한다. `users.ai_restricted=1` 은 방어 모드와 무관하게 항상 적용(n8n 조치용).
- 내부 API `GET /internal/api/v1/flag` (Bearer 토큰). 로그에 `via=direct|gateway`, `token_fp`(토큰 해시 앞부분)만 남기고 원문은 남기지 않는다.

## 적용 순서
1. `ai-agent` 브랜치 병합.
2. DB 마이그레이션(root): `python scripts/migrate_chat.py` (여러 번 실행해도 안전, 기존 대화는 "이전 대화"로 묶임).
3. 서버 `.env` 추가:
   ```
   AI_MODE=ollama
   DEFENSE_MODE=on
   LAB_INTERNAL_API_TOKEN=<팀 채팅으로 공유한 값>
   LAB_INTERNAL_API_FLAG=<팀 채팅으로 공유한 값>
   ```
   (`NEXUS_OLLAMA_ENABLED=1` 도 ollama 모드로 취급. `AI_MODE=mock` 이면 모델 없이 `/tool 이름 {JSON}` 으로 게이트웨이만 시험 가능.)
4. 재시작 후 `/chat` 에서 질문 → 답이 오고, 대시보드에 `ai_request`·`ai_tool_call`·`ai_tool_deny` 등이 보이는지 확인.

## n8n 연동 참고
- n8n 이 `users.ai_restricted` 를 바꾸려면 n8n 용 DB 계정에 `GRANT UPDATE (ai_restricted) ON nexus.users` 가 필요하다(앱 계정 `nexus_app` 에는 일부러 주지 않음). 진혜정/홍주형 확인.
- GELF 필드 추가: tool, mode, conversation_id, via, token_fp, api_path, ms, chars, resource_id.

## 아직 안 된 것
- 첨부파일 내용 읽기, 스트리밍(답이 한 번에 오고 화면에서 타이핑 효과만 냄).
- 실제 Ollama 로 한 전체 시험은 이시헌 PC 에서만 확인. 서버 DB 에서의 pytest 는 병합 후 실행.
