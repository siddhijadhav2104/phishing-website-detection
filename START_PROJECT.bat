@echo off
setlocal
title Phishing Website Detection - Start

cd /d "%~dp0"

echo ============================================================
echo   PHISHING WEBSITE DETECTION USING MACHINE LEARNING
echo ============================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python was not found.
  echo Install Python 3.11 or 3.12 and tick "Add Python to PATH".
  pause
  exit /b 1
)

where node >nul 2>&1
if errorlevel 1 (
  echo ERROR: Node.js was not found.
  echo Install Node.js LTS, then run this file again.
  pause
  exit /b 1
)

if not exist "backend\venv\Scripts\python.exe" (
  echo [1/5] Creating Python virtual environment...
  python -m venv backend\venv
  if errorlevel 1 goto :fail
)

echo [2/5] Installing backend dependencies...
call backend\venv\Scripts\python.exe -m pip install --upgrade pip
call backend\venv\Scripts\python.exe -m pip install -r backend\requirements.txt
if errorlevel 1 goto :fail

if not exist "backend\models\phishing_model.pkl" (
  echo [3/5] Training ML model...
  call backend\venv\Scripts\python.exe backend\train_model.py
  if errorlevel 1 goto :fail
) else (
  echo [3/5] ML model already exists.
)

if not exist "frontend\node_modules" (
  echo [4/5] Installing frontend dependencies...
  cd frontend
  call npm install
  if errorlevel 1 goto :fail
  cd ..
) else (
  echo [4/5] Frontend dependencies already installed.
)

echo [5/5] Starting backend and frontend...
start "Phishing Backend" cmd /k "cd /d %~dp0backend && venv\Scripts\python.exe app.py"
timeout /t 3 /nobreak >nul
start "Phishing Frontend" cmd /k "cd /d %~dp0frontend && npm run dev -- --host 127.0.0.1"
timeout /t 5 /nobreak >nul

start "" "http://localhost:5173"
echo.
echo Project started.
echo Website: http://localhost:5173
echo.
echo Keep the two terminal windows open while using the project.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo   SETUP FAILED
echo ============================================================
echo Read the error above, fix the indicated dependency, and run
echo START_PROJECT.bat again.
pause
exit /b 1
