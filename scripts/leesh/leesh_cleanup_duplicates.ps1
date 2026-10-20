# 중복 탐지 규칙 정리: 2026-10-20 10:28 실행에서 새로 만든 'NEXUS T*/R1/W1' 규칙(설명에 '이시헌, 2026-10-20')을
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
    $notifs = @{}; (Invoke-NexusGraylog GET '/api/events/notifications?per_page=200').notifications | ForEach-Object { $notifs[$_.id] = $_ }
    $defs = (Invoke-NexusGraylog GET '/api/events/definitions?per_page=300').event_definitions
    foreach ($d in $defs) {
        $names = (@($d.notifications) | ForEach-Object { $n = $notifs[$_.notification_id]; if ($n) { "$($n.title) <$($n.config.url -replace '\?.*$','')>" } }) -join ', '
        if ($d.description -match '이시헌, 2026-10-20') {
            try { $null = Invoke-NexusGraylog PUT "/api/events/definitions/$($d.id)/unschedule"; Say FIX "새 중복 규칙 일시중지: $($d.title)" '삭제 아님, Graylog 에서 다시 켤 수 있음' }
            catch { Say FAIL "일시중지 실패: $($d.title)" $_.Exception.Message }
        } elseif ($d.title -match 'NEXUS') {
            Say OK "기존 규칙 유지: $($d.title)" ("조건: " + $d.config.query + " | 알림: " + $(if ($names) { $names } else { '없음' }))
        }
    }
    (Invoke-NexusGraylog GET '/api/system/inputstates').states | ForEach-Object { Say INFO "입력 $($_.message_input.title)" "$($_.message_input.attributes.port) $($_.state)" }
} catch { Say FAIL 'Graylog API' ($_.ErrorDetails.Message + ' ' + $_.Exception.Message) }
$H = $null
$out = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) ('docs\이시헌_중복정리_' + (Get-Date -Format 'yyyyMMdd_HHmm') + '.txt')
$report | Set-Content -Path $out -Encoding UTF8
Write-Host "`n결과 저장: $out"
