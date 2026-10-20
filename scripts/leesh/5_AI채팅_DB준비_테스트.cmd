@echo off
chcp 65001 >nul
cd /d "%~dp0..\.."
echo [1/2] DB 준비(대화방 표/열 추가, 여러 번 실행해도 안전)
.venv\Scripts\python.exe scripts\migrate_chat.py
echo.
echo [2/2] 전체 테스트(몇 분 걸릴 수 있음). 결과는 docs\AI채팅_테스트결과.txt 에도 저장됩니다.
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider > docs\AI채팅_테스트결과.txt 2>&1
type docs\AI채팅_테스트결과.txt | more
echo.
echo 끝. 마지막 줄의 passed / failed 를 확인하세요.
pause
