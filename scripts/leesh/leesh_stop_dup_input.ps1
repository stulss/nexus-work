# 중복 입력 정리(Wazuh 5140 이중 수신 방지). 원래: 중복 탐지 규칙 정리: 2026-10-20 10:28 실행에서 새로 만든 'NEXUS T*/R1/W1' 규칙(설명에 '이시헌, 2026-10-20')을
# 삭제하지 않고 일시중지(unschedule)한다. 기존 '[NEXUS] ...' 규칙은 그대로 둔다. 기존 규칙과 연결된 알림을 보고한다.
param([string]$Graylog = 'http://127.0.0.1:9000')
$ErrorActionPreference = 'Continue'; $ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$report = New-Object System.Collections.Generic.List[string]
function Say($s, $i, $d = '') { $l = "[$s] $i" + $(if ($d) { " - $d" } else { '' }); Write-Host $l -ForegroundColor (@{OK='Green';FIX='Cyan';WARN='Yellow';FAIL='Red';INFO='Gray'}[$s]); $report.Add($l) }

$u = Read-Host 'Graylog 사용자 이름(그냥 Enter = admin)'; if (-not $u) { $u = 'admin' }
$pw = Read-Host 'Graylog 비밀번호' -AsSecureString
$c = New-Object System.Management.Automation.PSCredential($u, $pw)
$H = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($u + ':' + $c.GetNetworkCredential().Password)); 'X-Requested-By' = 'nexus-leesh'; Accept = 'application/json' }
function Invoke-NexusGraylog($method, $path) {
    $r = Invoke-WebRequest -Uri "$Graylog$path" -Method $method -Headers $H -UseBasicParsing -TimeoutSec 20
    $ms = New-Object IO.MemoryStream; $r.RawContentStream.CopyTo($ms)
    $t = [Text.Encoding]::UTF8.GetString($ms.ToArray()); if ($t) { $t | ConvertFrom-Json }
}
try {
    $st = (Invoke-NexusGraylog GET '/api/system/inputstates').states
    foreach ($s in $st) {
        if ($s.message_input.title -eq 'NEXUS Wazuh syslog UDP 5140') {
            if ($s.state -eq 'RUNNING') { $null = Invoke-NexusGraylog DELETE "/api/system/inputstates/$($s.id)"; Say FIX '중복 입력 정지: NEXUS Wazuh syslog UDP 5140' '삭제 아님. 기존 Wazuh Alerts(JSON 5140) 입력만 사용' }
            else { Say OK '중복 입력은 이미 정지됨' }
        }
    }
    Start-Sleep 2
    (Invoke-NexusGraylog GET '/api/system/inputstates').states | ForEach-Object { Say INFO "입력 $($_.message_input.title)" "$($_.message_input.attributes.port) $($_.state)" }
} catch { Say FAIL 'Graylog API' ($_.ErrorDetails.Message + ' ' + $_.Exception.Message) }
$H = $null
$out = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) ('docs\이시헌_입력정리_' + (Get-Date -Format 'yyyyMMdd_HHmm') + '.txt')
$report | Set-Content -Path $out -Encoding UTF8
Write-Host "`n결과 저장: $out"
