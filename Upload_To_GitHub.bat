@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title NetworkOptimizer - upload to GitHub
rem SAFE UPLOAD: no token or password is ever written in this file or in the
rem project. Git Credential Manager (installed with Git for Windows) opens a
rem browser sign-in the first time and stores the login in Windows Credential
rem Manager - outside the project folder.
call _common.bat || (pause & exit /b 1)
where git >nul 2>&1 || (echo Git is not installed: https://git-scm.com/download/win & pause & exit /b 1)

if not exist ".git" git init -b main >nul
git config user.name >nul 2>&1 || (set /p GN=Your GitHub user name: & git config user.name "!GN!")
git config user.email >nul 2>&1 || (set /p GE=Your GitHub e-mail ^(or the noreply address^): & git config user.email "!GE!")

git add -A
echo Checking for credentials and personal data...
%PY% tools\check_secrets.py
if errorlevel 1 (
  git reset -q
  echo Nothing was uploaded. Remove the items above and try again.
  pause & exit /b 1
)

git diff --cached --quiet && (echo No new changes to commit.) || git commit -q -m "NetworkOptimizer update %date% %time%"

git remote get-url origin >nul 2>&1
if errorlevel 1 (
  set /p REPO=GitHub repository URL ^(https://github.com/USER/REPO.git^): 
  echo !REPO! | findstr /c:"@" >nul && (echo Do not put a user name or token inside the URL. & pause & exit /b 1)
  echo !REPO! | findstr /b /c:"https://github.com/" >nul || (echo The URL must start with https://github.com/ & pause & exit /b 1)
  git remote add origin "!REPO!"
)
for /f "delims=" %%u in ('git remote get-url origin') do set "CUR=%%u"
echo !CUR! | findstr /c:"@" >nul && (echo The saved remote URL contains credentials. Fix it with: git remote set-url origin https://github.com/USER/REPO.git & pause & exit /b 1)

git push -u origin main
if errorlevel 1 (echo Push failed. Check the repository URL and your sign-in. & pause & exit /b 1)
echo Upload complete.
pause
endlocal
