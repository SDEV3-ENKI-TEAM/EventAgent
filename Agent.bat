@echo off
:: ────────────────────────────────
:: 1. 배치 파일이 있는 절대 경로를 BASEDIR 변수에 저장
for %%I in ("%~f0") do set "BASEDIR=%%~dpI"
if "%BASEDIR:~-1%"=="\" set "BASEDIR=%BASEDIR:~0,-1%"

:: ────────────────────────────────
:: 2. Sigma Matcher
start "Sigma Matcher" cmd /k "cd ""%BASEDIR%\sigma_matcher"" && sigma_matcher.exe"

:: ────────────────────────────────
:: 3. OpenTelemetry Collector
start "OpenTelemetry Collector" cmd /k ^
  "cd ""%BASEDIR%\otel\otelcol-contrib\otelcol-contrib"" && otelcol-contrib.exe --config otel-collector-config.yaml"

:: ────────────────────────────────
:: 4. Python API Server
start "Python API Server" cmd /k ^
  "cd ""%BASEDIR%\pythonapi"" && python -m venv venv && call venv\Scripts\activate.bat && uvicorn app:app --host 0.0.0.0 --port 8080 --reload"

:: ────────────────────────────────
:: 5. Jaeger
start "Jaeger" cmd /k ^
  "cd ""%BASEDIR%\jaeger"" && set SPAN_STORAGE_TYPE=opensearch&& set ES_TAGS_AS_FIELDS_ALL=true&& set OTEL_TRACES_SAMPLER=always_off&& .\jaeger-all-in-one.exe --collector.otlp.grpc.host-port=:4317 --collector.otlp.http.host-port=:4318 --es.server-urls=https://search-eventagentservice-px5xppytlfm2nbijkhrd2z7lp4.ap-northeast-2.es.amazonaws.com  --es.tls.enabled=true --es.num-replicas=2 --es.username=enki_sdev --es.password=macbyh-nybpo0-Suxsyw"

:: ────────────────────────────────
:: 6. SysmonAgent 
set "SYSPATH=%BASEDIR%\SysmonAgent"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process cmd.exe -Verb RunAs -ArgumentList '/k cd /d \"\"%SYSPATH%\"\" & SysmonAgent.exe'"

