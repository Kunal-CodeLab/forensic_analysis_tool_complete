@echo off
title 🔍 Forensic Tool Setup - by ॐNIKKI彡
echo Checking for Python...

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python not found. Installing now...
    curl -o python_installer.exe https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe
    start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
    echo Python installed successfully.
) ELSE (
    echo Python already installed.
)

echo Installing required libraries using pip...
python -m pip install --upgrade pip
python -m pip install pandas
python -m pip install psutil
python -m pip install pyautogui

echo All dependencies installed.

:: Run the main tool
echo Starting the Forensic Tool...
python launch_gui.py

pause
