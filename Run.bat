@echo off
setlocal
cd /d "%~dp0"
title NetworkOptimizer
call _common.bat || (pause & exit /b 1)
rem Runs as a NORMAL user. Administrator permission is requested by the app
rem only when you apply or restore a setting.
where pythonw >nul 2>&1 && (start "" pythonw -m netoptimizer %* & exit /b 0)
%PY% -m netoptimizer %*
if errorlevel 1 pause
endlocal
