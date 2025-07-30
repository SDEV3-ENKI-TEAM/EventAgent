@echo off
:: ────────────────────────────────
:: ① 배치 파일이 있는 절대 경로를 BASEDIR 변수에 저장
for %%I in ("%~f0") do set "BASEDIR=%%~dpI"
if "%BASEDIR:~-1%"=="\" set "BASEDIR=%BASEDIR:~0,-1%"

:: ────────────────────────────────
:: ② Sigma Matcher
start "Sigma Matcher" cmd /k "cd ""%BASEDIR%\sigma_matcher"" && sigma_matcher.exe"

:: ────────────────────────────────
:: ③ OpenTelemetry Collector
start "OpenTelemetry Collector" cmd /k ^
  "cd ""%BASEDIR%\otel\otelcol-contrib"" && otelcol-contrib.exe --config otel-collector-config.yaml"

:: ────────────────────────────────
:: ④ Python API Server
start "Python API Server" cmd /k ^
  "cd ""%BASEDIR%\pythonapi"" && python -m venv venv && call venv\Scripts\activate.bat && uvicorn app:app --host 0.0.0.0 --port 8080 --reload"

:: ────────────────────────────────
:: ⑤ SysmonAgent 
set "SYSPATH=%BASEDIR%\SysmonAgent"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%SYSPATH%\"\" & SysmonAgent.exe'"

