@echo off
setlocal
cd /d "%~dp0"
title NetworkOptimizer - build EXE
call _common.bat || (pause & exit /b 1)
echo Running tests first...
%PY% -m unittest discover -s . -p "test_*.py" -t . || (echo Tests failed - build stopped. & pause & exit /b 1)
echo Installing PyInstaller (build tool only, the app itself needs no packages)...
%PY% -m pip install --upgrade pyinstaller pywebview || (echo pip failed. & pause & exit /b 1)
%PY% -m PyInstaller --noconfirm --clean --onefile --windowed --collect-all webview --name NetworkOptimizer ^
  --add-data "netoptimizer\ui\static;netoptimizer\ui\static" ^
  --add-data "netoptimizer\data;netoptimizer\data" ^
  launcher.py
if errorlevel 1 (echo Build failed. & pause & exit /b 1)
echo.
echo  Done: dist\NetworkOptimizer.exe
pause
endlocal
