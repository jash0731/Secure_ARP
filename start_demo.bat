@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m secure_arp --demo
  goto done
)
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -m secure_arp --demo
  goto done
)
python -m secure_arp --demo
:done
pause
