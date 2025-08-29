# jaeger_dump_all_tracelevel_filtered.ps1
# - 시간 제약 없이 전체 트레이스를 trace-<traceID>.json 으로 저장
# - jaeger-all-in-one 등 메타 트래픽 제외

$JaegerBase = "http://localhost:16686"
$OutDir = "out_trace"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 제외할 서비스/오퍼레이션
$ExcludeServices   = @('jaeger-all-in-one')
$ExcludeOperations = @('/api/services','/api/operations','/api/traces')

Write-Host "[*] Jaeger Query =" $JaegerBase
Write-Host "[*] Output dir   =" (Resolve-Path $OutDir)

# 1) 서비스 목록
$servicesUrl = "$JaegerBase/api/services"
$svcResp = Invoke-RestMethod -Method GET -Uri $servicesUrl -TimeoutSec 60
$services = $svcResp.data | Where-Object { $_ -and ($ExcludeServices -notcontains $_) }
if (-not $services) { Write-Error "저장 대상 서비스가 없습니다."; exit 0 }

# 2) 시간 범위 없음 → 전체 검색
# Jaeger API 호출에서 start/end 파라미터 제거

# 3) 서비스별 트레이스 ID 수집
$traceIdSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($svc in $services) {
  $url = "{0}/api/traces?service={1}&limit=10000" -f `
    $JaegerBase, [System.Uri]::EscapeDataString($svc)
  try {
    $resp = Invoke-RestMethod -Method GET -Uri $url -TimeoutSec 300
  } catch { continue }

  if ($resp -and $resp.data) {
    foreach ($t in $resp.data) {
      if ($ExcludeOperations.Count -gt 0) {
        $ops = @($t.spans | ForEach-Object { $_.operationName }) | Select-Object -Unique
        $onlyExcluded = ($ops | Where-Object { $ExcludeOperations -notcontains $_ }).Count -eq 0
        if ($onlyExcluded) { continue }
      }
      if ($t.traceID) { [void]$traceIdSet.Add($t.traceID) }
    }
  }
}

if ($traceIdSet.Count -eq 0) { Write-Host "[-] 저장 대상 트레이스가 없습니다."; exit 0 }

# 4) 각 TraceID 상세 조회 및 저장
$idx = 0
foreach ($tid in $traceIdSet) {
  $idx++
  $detailUrl = "$JaegerBase/api/traces/$tid"
  try {
    $detail = Invoke-RestMethod -Method GET -Uri $detailUrl -TimeoutSec 300
  } catch { continue }

  $traceObj = $null
  if ($detail -and $detail.data -and $detail.data.Count -ge 1) { $traceObj = $detail.data[0] } else { continue }

  $procMap = $traceObj.processes.PSObject.Properties.Value
  $serviceNames = @()
  foreach ($p in $procMap) {
    if ($p.serviceName) { $serviceNames += $p.serviceName }
  }
  if ($serviceNames | Where-Object { $ExcludeServices -contains $_ }) { continue }

  if ($ExcludeOperations.Count -gt 0) {
    $ops2 = @($traceObj.spans | ForEach-Object { $_.operationName }) | Select-Object -Unique
    $onlyExcluded2 = ($ops2 | Where-Object { $ExcludeOperations -notcontains $_ }).Count -eq 0
    if ($onlyExcluded2) { continue }
  }

  $outFile = Join-Path $OutDir ("trace-{0}.json" -f $tid)
  if (-not (Test-Path $outFile)) {
    $json = $traceObj | ConvertTo-Json -Depth 100
    Set-Content -Path $outFile -Value $json -Encoding UTF8
  }
}

Write-Host ("[✔] 완료: {0}개 트레이스 파일 저장(메타 트래픽 제외)." -f ((Get-ChildItem $OutDir -File).Count))
