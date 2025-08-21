@echo off
:: ────────────────────────────────
:: 1. 배치 파일이 있는 절대 경로를 BASEDIR 변수에 저장
for %%I in ("%~f0") do set "BASEDIR=%%~dpI"
if "%BASEDIR:~-1%"=="\" set "BASEDIR=%BASEDIR:~0,-1%"

:: ────────────────────────────────
:: 2. Sigma Matcher
start "Sigma Matcher" cmd /k "cd ""%BASEDIR%\sigma_matcher"" && sigma_matcher.exe -ttl=1m -maxspans=100 -interval=1m"

:: ────────────────────────────────
:: 3. OpenTelemetry Collector
start "OpenTelemetry Collector" cmd /k ^
  "cd ""%BASEDIR%\otel\otelcol-contrib\otelcol-contrib"" && otelcol-contrib.exe --config otel-collector-config.yaml"

:: ────────────────────────────────
:: 6. SysmonAgent 
set "SYSPATH=%BASEDIR%\SysmonAgent"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%SYSPATH%\"\" & SysmonAgent.exe'"

