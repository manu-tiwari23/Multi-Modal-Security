@echo off
echo ========================================================
echo   MMS ESP32 Alert System - Automated Firmware Flasher
echo ========================================================
echo.
echo Target Serial Port: COM6
echo.
echo *** HARDWARE INSTRUCTION ***
echo Press and HOLD the physical "BOOT" (or "IO0") button on your
echo ESP32 board right now, then press any key to start upload.
echo Once you see "Writing at 0x00010000... (xx %)", release the button.
echo.
pause
"C:\Program Files\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe" upload -p COM6 --fqbn esp32:esp32:esp32 "%~dp0firmware\mms_alert_esp32"
echo.
if %ERRORLEVEL% EQU 0 (
    echo [+] Firmware uploaded successfully!
) else (
    echo [-] Upload failed. Make sure to hold BOOT during the connection attempt.
)
pause

