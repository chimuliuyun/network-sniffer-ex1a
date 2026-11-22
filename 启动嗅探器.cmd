@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
call "%~dp0src\find_python.cmd"
if errorlevel 1 goto failed
if defined PY_GUI (
    start "" "%PY_GUI%" %PY_ARGS% -B -X utf8 "%~dp0src\gui.py" %*
    exit /b
)
"%PY_EXE%" %PY_ARGS% -B -X utf8 "%~dp0src\gui.py" %*
if not errorlevel 1 exit /b 0
:failed
pause
exit /b 1
