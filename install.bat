@echo off
echo 🔧 Installing SIEM Tool Dependencies...
echo =========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.7 or higher.
    pause
    exit /b 1
)

REM Install required packages
echo 📦 Installing Python packages...
pip install -r requirements.txt

if errorlevel 1 (
    echo ❌ Installation failed. Please check your internet connection.
    pause
    exit /b 1
)

echo ✅ Installation complete!
echo.
echo 🚀 To start the SIEM tool, run:
echo    python run_siem.py
pause