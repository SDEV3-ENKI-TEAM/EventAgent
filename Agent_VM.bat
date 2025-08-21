@echo off
:: ────────────────────────────────
:: 1. 배치 파일이 있는 절대 경로를 BASEDIR 변수에 저장
for %%I in ("%~f0") do set "BASEDIR=%%~dpI"
if "%BASEDIR:~-1%"=="\" set "BASEDIR=%BASEDIR:~0,-1%"

:: ────────────────────────────────
:: 2. Sigma Matcher
set "SIGPATH=%BASEDIR%\sigma_matcher"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%SIGPATH%\"\" & sigma_matcher.exe -ttl=1m -maxspans=100 -interval=1m'"

:: ────────────────────────────────
:: 3. OpenTelemetry Collector
set "OTELPATH=%BASEDIR%\otel\otelcol-contrib\otelcol-contrib"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%OTELPATH%\"\" & otelcol-contrib.exe --config otel-collector-config-onlyjaeger.yaml'"

:: ────────────────────────────────
:: 5. Jaeger
set "JAEGERPATH=%BASEDIR%\jaeger"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%JAEGERPATH%\"\" & jaeger-all-in-one.exe -- collector.otlp.http.port 4318 -- query.http-port 16686'"


:: ────────────────────────────────
:: 6. SysmonAgent 
set "SYSPATH=%BASEDIR%\SysmonAgent"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%SYSPATH%\"\" & SysmonAgent.exe'"

