@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0leesh_check_and_configure.ps1" -Apply
pause
