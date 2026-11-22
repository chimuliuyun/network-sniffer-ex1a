@echo off
where pythonw.exe >nul 2>nul
if not errorlevel 1 (
    start "" pythonw.exe -B "%~dp0src\gui.py" %*
    exit /b
)
python -B "%~dp0src\gui.py" %*
if errorlevel 1 pause
