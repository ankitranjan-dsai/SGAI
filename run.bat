@echo off
REM SGAI - double-click launcher for Windows.
REM
REM Double-clicking a ".ps1" opens Notepad instead of running it, so use this
REM ".bat": Windows runs it in a command window on double-click. It launches the
REM PowerShell script with the execution policy bypassed for this run only.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1"
echo.
echo SGAI has stopped. Press any key to close this window.
pause >nul
