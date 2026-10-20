# 포털 서버(192.168.3.14) 적용 안내 — Graylog 로그 전송·Ollama 연결

작성: 이시헌 · 2026-10-20 · 적용: 홍주형(서버 담당)

보안 대시보드(`/admin/audit`)의 위협 지표 8종과 404 스캔을 Graylog(192.168.3.10)가 같은 이벤트 이름으로 탐지하도록, 포털이 `security.jsonl`에 쓰는 이벤트를 GELF로도 보냅니다. 파일 로그와 대시보드는 그대로 유지됩니다.

## 1. 파일 복사

이시헌 PC의 `C:\nexus-work\nexus_team_integration.py`를 서버의 저장소 루트(`run.py`와 같은 폴더)에 복사합니다. DB·권한은 건드리지 않는 모듈입니다.

## 2. `app/__init__.py`에 두 줄 추가

`app.config.setdefault("CHAT_RESPONDER", ...)` 줄 바로 아래:

```python
    from nexus_team_integration import init_app as init_team_integration
    init_team_integration(app)
```

## 3. 서버 `.env`에 추가

```
NEXUS_GELF_ENABLED=1
NEXUS_GELF_HOST=192.168.3.10
NEXUS_GELF_PORT=12201
NEXUS_GELF_SOURCE=nexus-portal-server
NEXUS_OLLAMA_ENABLED=1
OLLAMA_URL=http://192.168.3.10:11434
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_TIMEOUT_SECONDS=60
```

- `run_integrated.py`(옛 `app.monitoring` 브리지)로 띄우지 말고 `run.py`로 띄웁니다. 두 GELF 전송기가 같이 켜지면 모듈이 기동을 막습니다.
- AI 응답이 문제면 `NEXUS_OLLAMA_ENABLED=0`만 바꾸면 기존 mock 응답으로 돌아갑니다(작업 계획서 7장 "환경변수 하나로 전환").

## 4. 재시작 후 확인

1. 다른 PC에서 `http://192.168.3.14:5070/no-such-page` 한 번 열기.
2. Graylog 검색(`http://192.168.3.10:9000`)에서 `event_type:not_found` → `src_ip`가 요청한 PC 주소인지 확인.
3. 포털 AI 어시스턴트에 짧은 질문 → 20초 안팎에 답이 오고, 대시보드에 `ai_request`·`ai_response`가 남는지 확인.

## Graylog 탐지 규칙(이벤트 이름이 대시보드와 같음)

| 규칙 | 대시보드 지표 | 조건(초기값) |
|---|---|---|
| T1 | 로그인 실패 | 같은 출발지 5분 5회 |
| R1 | 로그인 실패(계정) | 같은 계정 5분 3회 |
| T2 | 잠긴 계정으로 로그인 시도 | 1회 |
| R1 | 계정 잠금 발생 | 1회 |
| T4 | 속도 제한 차단 | 같은 출발지 5분 10회 |
| T5 | CSRF 차단 | 같은 출발지 5분 5회 |
| T6 | 의심 입력(SQLi·XSS 등) | 같은 출발지·유형 5분 3회 |
| T7 | 업로드 거부 | 같은 출발지 10분 3회 |
| T8 | 권한 거부(미로그인 제외) | 같은 출발지·계정 5분 5회 |
| W1 | 404 스캔 | 같은 출발지 1분 30회 |

모든 규칙은 기존 n8n 알림(→ Discord)에 연결되고, 같은 출발지는 5분 동안 다시 알리지 않습니다. 임계값은 10/22 오탐 조정 때 김태빈과 맞춥니다.

## Wazuh agent(선택, 김태빈 담당과 겹침)

서버에 Wazuh agent를 설치해 manager `192.168.3.10`(1514/1515)에 등록하면, 공용 설정에 넣어 둔 FIM(`C:\nexus-work\instance\uploads`, `app\templates`, `app\static`)이 자동 적용됩니다. 서버의 저장소 경로가 다르면 알려 주세요.
