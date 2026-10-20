@echo off
chcp 65001 >nul
cd /d "%~dp0..\.."
echo ai-agent 브랜치를 내 GitHub(onedotfour88-lgtm/nexus-work)에 올립니다. 로그인 창이 뜨면 로그인하세요.
git push -u leesh ai-agent
echo.
echo 위에 오류가 없으면 GitHub 에서 ai-agent 브랜치를 확인하세요.
pause
