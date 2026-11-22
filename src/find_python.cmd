@echo off
rem Set PY_EXE, PY_GUI and PY_ARGS for the calling launcher.
set "PY_EXE="
set "PY_GUI="
set "PY_ARGS="
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=false"
set "PY_PROBE=import sys, tkinter; sys.exit(sys.version_info[:2] < (3, 10))"
for /f "delims=" %%P in ('where.exe py.exe 2^>nul') do (
    "%%P" -3 -I -B -c "%PY_PROBE%" >nul 2>&1
    if not errorlevel 1 (
        set "PY_EXE=%%P"
        if exist "%%~dpPpyw.exe" set "PY_GUI=%%~dpPpyw.exe"
        set "PY_ARGS=-3"
        exit /b 0
    )
)
for /f "delims=" %%P in ('where.exe python.exe 2^>nul') do (
    if /i not "%%P"=="%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" (
        "%%P" -I -B -c "%PY_PROBE%" >nul 2>&1
        if not errorlevel 1 (
            set "PY_EXE=%%P"
            if exist "%%~dpPpythonw.exe" set "PY_GUI=%%~dpPpythonw.exe"
            exit /b 0
        )
    )
)
echo 源码版需要带 Tcl/Tk 的 Python 3.10 或更高版本。
echo x64 电脑也可以解压便携版，直接双击里面的 EXE。
exit /b 1
