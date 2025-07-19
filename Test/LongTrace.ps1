param(
    [int]$Depth    = 0,   # 현재 깊이
    [int]$MaxDepth = 3    # 루트 0 기준 (3 → 총 4 단계)
)

# 현재 프로세스·부모 PID 출력
$parent = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
Write-Host "DEPTH=$Depth  PID=$PID  PPID=$parent"

if ($Depth -lt $MaxDepth) {
    $next = $Depth + 1

    if ($Depth % 2 -eq 0) {
        # 짝수 단계는 CMD로 전환
        $cmdArgs = "/k powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Depth $next -MaxDepth $MaxDepth"
        Start-Process -FilePath cmd.exe -ArgumentList $cmdArgs -WindowStyle Normal
    }
    else {
        # 홀수 단계는 PowerShell 유지
        $psArgs = @(
            "-NoLogo", "-NoExit",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-Depth",  $next,
            "-MaxDepth", $MaxDepth
        )
        Start-Process -FilePath powershell -ArgumentList $psArgs -WindowStyle Normal
    }
}
else {
    # 리프 단계: GUI 앱 두 개 실행
    Start-Process notepad
    Start-Process calc
}

# 창이 즉시 닫히지 않도록 대기
Read-Host "Press <Enter> to close depth $Depth shell"
