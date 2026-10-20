@echo off
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File %~dp0leesh_check_and_configure.ps1 -Apply -FirewallOnly'"
