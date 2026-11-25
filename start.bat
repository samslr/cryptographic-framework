@echo off
TITLE CyberVault - Cryptographic Operations Platform
COLOR 0B

echo ======================================================================
echo           CYBERVAULT - CRYPTOGRAPHIC OPERATIONS PLATFORM
echo   Modular Multi-Algorithm Framework for Secure Data Protection
echo ======================================================================
echo.

cd /d "%~dp0"

IF NOT EXIST ".venv\Scripts\python.exe" (
    echo [*] Python virtual environment not found. Setting up .venv...
    py -3.14 -m venv .venv 2>nul || py -3 -m venv .venv 2>nul || python -m venv .venv
    IF NOT EXIST ".venv\Scripts\python.exe" (
        echo [!] Error: Failed to create virtual environment. Ensure Python 3.10+ is installed.
        pause
        exit /b 1
    )
    echo [*] Installing dependencies from requirements.txt...
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt
    echo [*] Dependencies installed successfully.
    echo.
)

echo [*] Starting CyberVault Application Server on http://127.0.0.1:5000...
echo [*] Press CTRL+C to stop the server at any time.
echo.

start "" http://127.0.0.1:5000

.venv\Scripts\python.exe app.py

pause
