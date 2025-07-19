# 이벤트 수집 Agent

Sysmon이 생성한 보안 이벤트를 OpenTelemetry Collector를 통해 Sigma 룰 매칭 엔진으로 전달하여 룰 위반 탐지를 하고 프로세스 행위를 Trace 형태로 만들어 Jaeger와 Opensearch를 사용하여 인덱싱하고 시각화합니다.

---

## 구성 요소

* **SysmonETWexporter**
  Windows Sysmon ETW(Event Tracing for Windows)에서 보안 이벤트를 수집하여 OTEL Collector(포트 4319)로 OTLP Trace 전송

* **otel-collector**
  수신한 스팬의 필드를 Sigma 룰 매칭에 맞게 **표준화(transform)** ▶ **Sigma Matcher(55680)** 로 전달 ▶ 매칭 결과가 포함된 스팬을 **Jaeger / 파일 / 디버그** 로 후단 전송

* **sigma\_matcher**
  OTLP gRPC 서버(55680). `sigma_matcher/rules/rules/windows` 디렉터리의 YAML 룰을 메모리에 올린 뒤 Collector에서 온 이벤트에 대해 룰 일치 여부를 판정하고, 매칭 시 `sigma.alert` 태그를 주입

* **OpenSearch 3.1 + Jaeger 1.56** (Docker Compose)
  ‑ OpenSearch 두 노드 클러스터가 Jaeger 인덱스(jaeger‑span‑*, jaeger‑service‑*)를 저장소로 제공
  ‑ OpenSearch Dashboards에서 **Observability ▶ Trace Analytics** 앱으로 Jaeger 인덱스를 시각화

---

## 사전 준비

1. **Windows**
2. **Sysmon** 설치 및 실행

```powershell
# 이벤트 필터가 포함된 구성 적용 후 실행
Sysmon64.exe -i -l -n -accepteula
Sysmon64.exe -c sysmonconfig-export.xml 
```

3. **Go 1.23**, **Docker & Compose** 설치

---

## 설정 및 실행

### 옵션 A : 사전 빌드 바이너리 실행

```powershell
# 0) 저장소 클론
git clone https://github.com/shhhlee/EventAgent.git

# 1) SysmonETWexporter
./SysmonETWexporter.exe

# 2) sigma_matcher
./sigma_matcher.exe

# 3) OTEL Collector
압축 해제
otelcol-contrib --config otel-collector-config.yaml

# 4) OpenSearch · Jaeger · Dashboards (Docker)
docker compose pull
docker‑compose up -d
```

### 옵션 B : 소스 빌드

```powershell
# 0) 저장소 클론
git clone https://github.com/shhhlee/EventAgent.git

# 1) SysmonETWexporter
프로젝트 파일 압축 해제 후 빌드

# 2) sigma_matcher
cd sigma_matcher
go mod tidy
go build -o sigma_matcher main.go
./sigma_matcher

# 3) OTEL Collector
압축 해제
otelcol-contrib --config otel-collector-config.yaml

# 4) Docker Compose (OpenSearch · Jaeger · Dashboards)
docker compose pull
docker‑compose up -d
```

---

## OpenSearch 설명 & 템플릿

* **인덱스 템플릿**: Jaeger Collector가 처음 스팬을 적재할 때 자동으로 `jaeger-span-*`, `jaeger-service-*` 인덱스와 템플릿을 생성합니다.

---

## Trace Analytics에서 트레이스 확인

1. 브라우저에서 **OpenSearch Dashboards** 접속 → `http://localhost:5601`
2. 좌측 메뉴 **Observability ▶ Trace Analytics** 선택
3. 첫 진입 시 "데이터 소스 추가" 대화상자가 뜨면 **`jaeger-span-*`** 패턴을 추가하고 저장
4. **Traces** 탭에서 최근 트레이스 리스트가 나타나며, 원하는 Trace ID를 클릭해 세부 스팬 확인
5. **Sigma Alert**가 주입된 스팬은 Errors가 Yes로 나타남

---

## 테스트

```powershell
#cmd-ps-cmd-ps-notepad,calc
powershell.exe -ExecutionPolicy Bypass -File .\Test\LongTrace.ps1
```

* **SysmonETWexporter** → 실시간 이벤트 출력
* **OTEL Collector** → 데이터 표준화 및 전송 확인
* **sigma\_matcher** → "⚠️ Sigma 매칭" 메시지 확인
* **Jaeger UI(`http://localhost:16686`) / Dashboards(`http://localhost:5601`)** → 이벤트 확인 및 트레이스,스팬 조회

---
