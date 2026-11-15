@echo off
setlocal
cd /d "%~dp0"
title NetworkOptimizer - tests
call _common.bat || (pause & exit /b 1)
%PY% -m unittest discover -s . -p "test_*.py" -t . -v
if errorlevel 1 (echo. & echo  SOME TESTS FAILED.) else (echo. & echo  ALL TESTS PASSED.)
pause
endlocal
