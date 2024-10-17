@echo off
setlocal enabledelayedexpansion

rem Imposta il nome del computer e l'IP
set COMPUTER_NAME=%COMPUTERNAME%
set IP_ADDRESS=

rem Imposta il percorso del file di log
set LOG_FILE=C:\logMinitorProcess.log

rem Inizia il logging
echo %date% %time%: ------------------ >> %LOG_File%
echo %date% %time%: Inizio script batch >> %LOG_File%

for /f "delims=[] tokens=2" %%a in ('ping -4 -n 1 %ComputerName% ^| findstr [') do set IP_ADDRESS=%%a
echo %date% %time%: Network IP: %IP_ADDRESS% >> %LOG_File%

rem Controlla i servizi
set SERVICES=WinDefend Sense CSFalconService ir_agent
set SERVICE_STATUS=

timeout 120

for %%S in (%SERVICES%) do (
    sc query "%%S" | find "RUNNING" > nul
    if !ERRORLEVEL! EQU 0 (
        set SERVICE_STATUS=!SERVICE_STATUS!\"%%S\":\"running\",
    ) else (
        sc query "%%S" | find "STOPPED" > nul
        if !ERRORLEVEL! EQU 0 (
            rem Tenta di avviare il servizio fermo
            net start "%%S"
            timeout /t 10 > nul
            sc query "%%S" | find "RUNNING" > nul
            if !ERRORLEVEL! EQU 0 (
		echo %date% %time%: Servizio %%S Avviato >> %LOG_FILE%
                set SERVICE_STATUS=!SERVICE_STATUS!\"%%S\":\"running\",
            ) else (
                set SERVICE_STATUS=!SERVICE_STATUS!\"%%S\":\"stopped\",
            )
        ) else (
            set SERVICE_STATUS=!SERVICE_STATUS!\"%%S\":\"not installed\",
        )
    )
)

rem Verifica nel registro di Windows
set REG_PATH="HKEY_CURRENT_USER\Software\Policies\Microsoft\Office\16.0\Common\Security\Labels"
set REG_KEY="UseOfficeForLabelling"
for /f "tokens=3*" %%A in ('reg query %REG_PATH% /v %REG_KEY% 2^>nul') do (
    set REG_VALUE=%%A %%B
)

if defined REG_VALUE (
    echo %date% %time%: Chiave di registro %REG_PATH%\%REG_KEY% trovata, valore: %REG_VALUE% >> %LOG_FILE%
) else (
    set REG_VALUE="not found" 
    echo %date% %time%: Chiave di registro %REG_PATH%\%REG_KEY% non trovata >> %LOG_FILE%
)

rem Verifica dell'esistenza del file
set FILE_PATH="C:\Program Files (x86)\Microsoft Azure Information Protection\MSIP.App.exe"
if exist %FILE_PATH% (
    set FILE_STATUS=\"exists\"
    echo %date% %time%: File %FILE_PATH% trovato >> %LOG_FILE%
) else (
    set FILE_STATUS=\"not found\"
    echo %date% %time%: File %FILE_PATH% non trovato >> %LOG_FILE%
)

timeout 10

rem Rimuove spazi superflui
set REG_VALUE=%REG_VALUE:~0,-1%
rem Aggiungi reg_value e file_status all'oggetto services
set SERVICE_STATUS=!SERVICE_STATUS!\"reg_value\":\"%REG_VALUE%\",\"file_status\":%FILE_STATUS%

rem Rimuove l'ultima virgola e aggiusta la formattazione
rem if defined SERVICE_STATUS set SERVICE_STATUS={!SERVICE_STATUS!}

echo %SERVICE_STATUS%

rem Crea il corpo JSON
set JSON_BODY={\"name\":\"%COMPUTER_NAME%\",\"ip\":\"%IP_ADDRESS%\",\"user\":\"%USERNAME%\",\"services\":{%SERVICE_STATUS%}}


echo %date% %time%: %JSON_BODY% >> %LOG_File%

# rem Invio dei dati al server Node.js
# curl -k -X POST https://process.sampierana.com:5443/monitor -H "Content-Type: application/json" -d %JSON_BODY%


echo %date% %time%: Fine script batch >> %LOG_File%
echo %date% %time%: ------------------ >> %LOG_File%

endlocal

rem pause