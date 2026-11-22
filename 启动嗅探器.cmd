@echo off
python -B "%~dp0src\gui.py"
if errorlevel 1 pause
