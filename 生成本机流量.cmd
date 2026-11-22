@echo off
setlocal DisableDelayedExpansion
chcp 65001 >nul
call "%~dp0src\find_python.cmd"
if errorlevel 1 goto failed
"%PY_EXE%" %PY_ARGS% -B -X utf8 "%~dp0src\local_traffic.py"
if errorlevel 1 goto failed
pause
exit /b 0
:failed
pause
exit /b 1
