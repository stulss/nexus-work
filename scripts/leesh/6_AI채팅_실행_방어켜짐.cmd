@echo off
chcp 65001 >nul
cd /d "%~dp0..\.."
set DEFENSE_MODE=on
set AI_MODE=ollama
set LAB_INTERNAL_API_TOKEN=nxapi_local_test_token_0123456789abcd
set LAB_INTERNAL_API_FLAG=NXC{local-test-flag}
echo 포털을 시작합니다. 브라우저에서 http://127.0.0.1:5070/chat 을 여세요. 끄려면 이 창을 닫으세요.
echo DEFENSE_MODE=on  (Ollama 주소는 .env 의 OLLAMA_URL)
.venv\Scripts\python.exe run.py
pause
