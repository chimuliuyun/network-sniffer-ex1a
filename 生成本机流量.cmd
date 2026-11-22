@echo off
chcp 65001 >nul
python -B -X utf8 "%~dp0src\local_traffic.py"
pause
