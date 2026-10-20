@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0leesh_cleanup_duplicates.ps1"
pause
