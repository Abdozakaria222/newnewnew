@echo off
rem Shared helper: finds a working Python 3.9+ and stores the command in PY.
set "PY="
py -3 -c "import sys" >nul 2>&1 && set "PY=py -3"
if not defined PY python -c "import sys" >nul 2>&1 && set "PY=python"
if not defined PY (
  echo.
  echo  Python 3.9 or newer was not found.
  echo  Install it from https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
  echo  or run:  winget install Python.Python.3.12
  echo.
  exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >nul 2>&1
if errorlevel 1 (
  echo  Your Python is older than 3.9. Please install a newer version.
  exit /b 1
)
exit /b 0
