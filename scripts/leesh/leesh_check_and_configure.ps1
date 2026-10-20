# NEXUS WORK - 이시헌(네트워크 B + Ollama) 환경 점검·구성 스크립트
# 실행: VS Code 터미널(관리자 PowerShell 권장)에서
#   powershell -ExecutionPolicy Bypass -File C:\nexus-work\scripts\leesh\leesh_check_and_configure.ps1
# 옵션:
#   -Apply      : 점검 후 빠진 항목(Graylog 입력·탐지 규칙, 방화벽 규칙, Ollama 모델)을 실제로 만든다. 없으면 점검만 한다.
#   -SendTest   : Graylog 의 n8n 알림을 시험 발송한다(Discord 에 시험 메시지가 1건 간다).
# 비밀번호는 Graylog 로그인 창(Get-Credential)에만 입력하고, 파일·화면에 남기지 않는다.
param([switch]$Apply, [switch]$SendTest, [switch]$FirewallOnly,
      [string]$Graylog = 'http://127.0.0.1:9000',
      [string]$N8n = 'http://127.0.0.1:5678',
      [string]$Ollama = 'http://127.0.0.1:11434',
      [string]$OllamaModel = 'qwen2.5:3b',
      [string]$PortalServer = '192.168.3.14',
      [string[]]$TeamSubnets = @('192.168.3.0/24', '172.16.50.0/24'))

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$report = New-Object System.Collections.Generic.List[string]
function Say($status, $item, $detail = '') {
    $line = '[{0}] {1}{2}' -f $status, $item, $(if ($detail) { ' - ' + $detail } else { '' })
    $color = @{ OK = 'Green'; FIX = 'Cyan'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Gray' }[$status]
    Write-Host $line -ForegroundColor $color
    $report.Add($line)
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $FirewallOnly) {
Write-Host "`n=== 1. 컨테이너 상태 ===" -ForegroundColor White
$names = docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}' 2>$null
if (-not $names) { Say FAIL 'Docker' 'docker ps 실패 - Docker Desktop 실행 확인' }
foreach ($want in 'gl-graylog', 'n8n', 'ollama', 'wazuh') {
    $row = $names | Where-Object { $_ -match $want } | Select-Object -First 1
    if ($row) { $p = $row.Split('|'); Say OK "컨테이너 $($p[0])" $p[1] } else { Say FAIL "컨테이너 *$want*" '실행 중이 아님' }
}
$glPorts = (docker port gl-graylog 2>$null) -join '; '
Say INFO 'Graylog 공개 포트' $glPorts
$wazuhMgr = ($names | Where-Object { $_ -match 'wazuh' -and $_ -match 'manager' } | Select-Object -First 1)
if ($wazuhMgr) { $wazuhMgr = $wazuhMgr.Split('|')[0] }

Write-Host "`n=== 2. 장비 간 통신 ===" -ForegroundColor White
foreach ($t in @(@($PortalServer, 5070, '포털'), @('127.0.0.1', 9000, 'Graylog UI/API'), @('127.0.0.1', 5678, 'n8n'), @('127.0.0.1', 11434, 'Ollama'), @('127.0.0.1', 1514, 'Wazuh agent 수신'))) {
    $ok = Test-NetConnection -ComputerName $t[0] -Port $t[1] -InformationLevel Quiet -WarningAction SilentlyContinue
    Say $(if ($ok) { 'OK' } else { 'FAIL' }) "$($t[2]) $($t[0]):$($t[1])"
}
try { $h = Invoke-RestMethod "http://${PortalServer}:5070/healthz" -TimeoutSec 5; Say OK '포털 /healthz' $h.status } catch { Say FAIL '포털 /healthz' $_.Exception.Message }
$myIps = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(127|169\.254)' }).IPAddress -join ', '
Say INFO '이 PC 주소' $myIps

Write-Host "`n=== 3. Ollama ===" -ForegroundColor White
try {
    $tags = Invoke-RestMethod "$Ollama/api/tags" -TimeoutSec 10
    $models = @($tags.models.name)
    Say OK 'Ollama API' ('모델: ' + ($models -join ', '))
    if ($models -notcontains $OllamaModel) {
        if ($Apply) { Say FIX "모델 $OllamaModel 내려받기" '수 분 걸림'; docker exec ollama ollama pull $OllamaModel | Out-Null; Say OK "모델 $OllamaModel" '설치됨' }
        else { Say WARN "모델 $OllamaModel 없음" '-Apply 로 설치' }
    }
    $body = @{ model = $OllamaModel; stream = $false; messages = @(@{ role = 'user'; content = '한 문장으로 인사해 주세요.' }); options = @{ num_predict = 40 } } | ConvertTo-Json -Depth 5
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-RestMethod "$Ollama/api/chat" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json' -TimeoutSec 120
    Say OK 'Ollama 응답 시험' ('{0:N1}초, "{1}"' -f $sw.Elapsed.TotalSeconds, ($r.message.content -replace '\s+', ' ').Substring(0, [Math]::Min(40, $r.message.content.Length)))
    $bind = docker port ollama 11434 2>$null
    Say $(if ($bind -match '0\.0\.0\.0') { 'OK' } else { 'WARN' }) 'Ollama 외부 바인딩' "$bind (팀원 접속은 0.0.0.0 이어야 함)"
} catch { Say FAIL 'Ollama' $_.Exception.Message }

}
Write-Host "`n=== 4. 방화벽(팀원·포털 서버 접속 허용, 학원 LAN·VMnet2 만) ===" -ForegroundColor White
$rules = @(
    @('NEXUS Ollama 11434', 'TCP', 11434), @('NEXUS Graylog GELF 12201', 'UDP', 12201), @('NEXUS Graylog GELF TCP 12201', 'TCP', 12201),
    @('NEXUS Graylog UI 9000', 'TCP', 9000), @('NEXUS n8n 5678', 'TCP', 5678), @('NEXUS Wazuh agent 1514', 'TCP', 1514),
    @('NEXUS Wazuh enroll 1515', 'TCP', 1515), @('NEXUS pfSense syslog 1514', 'UDP', 1514))
foreach ($r in $rules) {
    $exists = Get-NetFirewallRule -DisplayName $r[0] -ErrorAction SilentlyContinue
    if ($exists) { Say OK "방화벽 $($r[0])" }
    elseif ($Apply -and $isAdmin) {
        New-NetFirewallRule -DisplayName $r[0] -Direction Inbound -Protocol $r[1] -LocalPort $r[2] -RemoteAddress $TeamSubnets -Action Allow -Profile Any | Out-Null
        Say FIX "방화벽 $($r[0])" ('허용: ' + ($TeamSubnets -join ', '))
    } else { Say WARN "방화벽 $($r[0]) 없음" $(if ($Apply) { '관리자 PowerShell 로 다시 실행' } else { '-Apply 로 생성' }) }
}

if (-not $FirewallOnly) {
Write-Host "`n=== 5. Wazuh ===" -ForegroundColor White
if ($wazuhMgr) {
    $so = docker exec $wazuhMgr sh -c "grep -A3 '<syslog_output>' /var/ossec/etc/ossec.conf" 2>$null
    if ($so -match 'gl-graylog|192\.168\.3\.10' -and $so -match '5140') { Say OK 'Wazuh → Graylog syslog 5140' } else { Say WARN 'Wazuh syslog_output' ($so -join ' ') }
    $agents = docker exec $wazuhMgr /var/ossec/bin/agent_control -l 2>$null
    $agents | Where-Object { $_ -match 'ID:' } | ForEach-Object { Say INFO 'Wazuh agent' ($_.Trim()) }
    if (-not ($agents -match [regex]::Escape($PortalServer))) { Say WARN '포털 서버 Wazuh agent' "$PortalServer agent 가 아직 등록되지 않음(김태빈·홍주형 PC 에서 설치 필요)" }
    $shared = docker exec $wazuhMgr sh -c "cat /var/ossec/etc/shared/default/agent.conf" 2>$null
    if ($shared -match 'nexus-work') { Say OK 'Wazuh FIM(포털 문서함·업로드)' }
    elseif ($Apply) {
        $tmp = Join-Path $PSScriptRoot 'wazuh_agent_nexus.conf'
        docker exec $wazuhMgr sh -c "cp /var/ossec/etc/shared/default/agent.conf /var/ossec/etc/shared/default/agent.conf.bak-nexus-$(Get-Date -Format yyyyMMddHHmmss)" | Out-Null
        docker cp $tmp "${wazuhMgr}:/tmp/nexus_agent.conf" | Out-Null
        docker exec $wazuhMgr sh -c "cat /tmp/nexus_agent.conf >> /var/ossec/etc/shared/default/agent.conf && chown wazuh:wazuh /var/ossec/etc/shared/default/agent.conf 2>/dev/null; /var/ossec/bin/verify-agent-conf" | ForEach-Object { Say INFO 'verify-agent-conf' $_ }
        Say FIX 'Wazuh FIM(포털 문서함·업로드)' 'shared/default/agent.conf 에 추가(백업 남김)'
    } else { Say WARN 'Wazuh FIM 설정에 nexus-work 경로 없음' '-Apply 로 추가' }
} else { Say FAIL 'Wazuh manager 컨테이너 없음' }

Write-Host "`n=== 6. n8n ===" -ForegroundColor White
try { $null = Invoke-WebRequest "$N8n/healthz" -UseBasicParsing -TimeoutSec 5; Say OK 'n8n /healthz' } catch { Say FAIL 'n8n' $_.Exception.Message }

Write-Host "`n=== 7. Graylog (입력·탐지 규칙·알림) ===" -ForegroundColor White
Write-Host 'Graylog 관리자 계정을 이 창에 입력하세요(비밀번호는 화면에 안 보이고 저장되지 않음).' -ForegroundColor Cyan
$glUser = Read-Host 'Graylog 사용자 이름(그냥 Enter = admin)'
if (-not $glUser) { $glUser = 'admin' }
$glPass = Read-Host 'Graylog 비밀번호' -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential($glUser, $glPass)
if ($cred) {
    $pair = '{0}:{1}' -f $cred.UserName, $cred.GetNetworkCredential().Password
    $H = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair)); 'X-Requested-By' = 'nexus-leesh'; Accept = 'application/json' }
    $pair = $null
    function Invoke-NexusGraylog($method, $path, $obj) {
        $p = @{ Uri = "$Graylog$path"; Method = $method; Headers = $H; TimeoutSec = 20 }
        if ($obj) { $p.Body = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Depth 30)); $p.ContentType = 'application/json; charset=utf-8' }
        Invoke-RestMethod @p
    }
    try {
        $inputs = (Invoke-NexusGraylog GET '/api/system/inputs').inputs
        $states = (Invoke-NexusGraylog GET '/api/system/inputstates').states
        $need = @(
            @{ title = 'NEXUS portal GELF UDP 12201'; type = 'org.graylog2.inputs.gelf.udp.GELFUDPInput'; port = 12201; why = '포털 보안 로그' },
            @{ title = 'NEXUS Wazuh syslog UDP 5140'; type = 'org.graylog2.inputs.syslog.udp.SyslogUDPInput'; port = 5140; why = 'Wazuh 경보' },
            @{ title = 'NEXUS pfSense syslog UDP 1514'; type = 'org.graylog2.inputs.syslog.udp.SyslogUDPInput'; port = 1514; why = 'pfSense filterlog(Could)' })
        foreach ($n in $need) {
            $hit = $inputs | Where-Object { $_.attributes.port -eq $n.port -and (($_.type -match 'udp|UDP') -eq ($n.type -match 'udp|UDP')) } | Select-Object -First 1
            if ($hit) {
                $st = ($states | Where-Object { $_.id -eq $hit.id }).state
                Say $(if ($st -eq 'RUNNING') { 'OK' } else { 'WARN' }) "Graylog 입력 $($hit.title)" "$($n.port) $st"
            } elseif ($Apply -and ($n.port -ne 1514 -or $glPorts -match '1514/udp')) {
                $cfg = @{ bind_address = '0.0.0.0'; port = $n.port; recv_buffer_size = 262144; number_worker_threads = 2 }
                if ($n.type -match 'GELF') { $cfg.decompress_size_limit = 8388608 } else { $cfg.store_full_message = $true; $cfg.allow_override_date = $true }
                $null = Invoke-NexusGraylog POST '/api/system/inputs' @{ title = $n.title; type = $n.type; global = $true; configuration = $cfg }
                Say FIX "Graylog 입력 $($n.title)" $n.why
            } else { Say WARN "Graylog 입력 $($n.port) 없음" $(if ($n.port -eq 1514) { 'gl-graylog 에 1514/udp 포트 공개가 없어 pfSense 로그는 수신 불가(Could 항목)' } else { '-Apply 로 생성' }) }
        }

        $notifs = (Invoke-NexusGraylog GET '/api/events/notifications?per_page=200').notifications
        $notif = $notifs | Where-Object { $_.title -match 'n8n|NEXUS|portal' -and $_.config.type -match 'http' } | Select-Object -First 1
        if (-not $notif) { $notif = $notifs | Where-Object { $_.config.type -match 'http' } | Select-Object -First 1 }
        if ($notif) { Say OK "Graylog → n8n 알림 '$($notif.title)'" ($notif.config.url -replace '\?.*$', '') } else { Say WARN 'Graylog HTTP 알림 없음' 'n8n Webhook 알림을 먼저 만들어야 Discord 로 감' }

        $defs = (Invoke-NexusGraylog GET '/api/events/definitions?per_page=300').event_definitions
        $have = @{}; $defs | ForEach-Object { $have[$_.title] = $_ }
        $scope = '_exists_:event_type AND _exists_:src_ip'
        # 보안 대시보드 위협 지표 8종 + R1 + 404 스캔. [제목, 조건, 묶음 필드, 임계값, 분, 우선순위]
        $R = @(
            @('NEXUS T1 로그인 실패 반복(출발지)', 'event_type:login_failure', @('src_ip'), 5, 5, 3),
            @('NEXUS R1 계정 대상 로그인 실패 3회+', 'event_type:login_failure', @('user'), 3, 5, 3),
            @('NEXUS T2 잠긴 계정으로 로그인 시도', 'event_type:login_locked', @('src_ip', 'user'), 1, 5, 3),
            @('NEXUS R1 계정 잠금 발생', 'event_type:account_locked', @('user', 'src_ip'), 1, 5, 4),
            @('NEXUS T4 속도 제한 차단 반복', 'event_type:rate_limited', @('src_ip'), 10, 5, 2),
            @('NEXUS T5 CSRF 차단 반복', 'event_type:csrf_fail', @('src_ip'), 5, 5, 2),
            @('NEXUS T6 의심 입력(SQLi·XSS·경로조작)', 'event_type:suspicious_input', @('src_ip', 'reason'), 3, 5, 3),
            @('NEXUS T7 업로드 거부 반복', 'event_type:upload_reject', @('src_ip'), 3, 10, 2),
            @('NEXUS T8 권한 거부 반복', 'event_type:authz_deny AND NOT reason:not_logged_in', @('src_ip', 'user'), 5, 5, 3),
            @('NEXUS W1 404 스캔(웹 스캐너)', 'event_type:not_found', @('src_ip'), 30, 1, 2))
        foreach ($x in $R) {
            $title, $q, $grp, $thr, $win, $prio = $x
            if ($have.ContainsKey($title)) {
                $d = $have[$title]; $linked = @($d.notifications).Count -gt 0
                Say $(if ($linked) { 'OK' } else { 'WARN' }) "탐지 규칙 $title" $(if ($linked) { '알림 연결됨' } else { '알림 미연결' })
                continue
            }
            $existingSame = $defs | Where-Object { $_.config.query -match [regex]::Escape(($q -split ' ')[0]) } | Select-Object -First 1
            if ($existingSame) { Say OK "기존 규칙 '$($existingSame.title)'" "$title 와 같은 이벤트를 이미 탐지함(새로 만들지 않음)"; continue }
            if (-not $Apply) { Say WARN "탐지 규칙 $title 없음" '-Apply 로 생성'; continue }
            $fs = @{}
            foreach ($f in @('src_ip', 'user')) { $fs[$f] = @{ data_type = 'string'; providers = @(@{ type = 'template-v1'; template = '${source.' + $f + '}'; require_values = $false }) } }
            $body = [ordered]@{
                title = $title; description = 'NEXUS 포털 보안 대시보드 위협 지표 연동(이시헌, 2026-10-20)'; priority = $prio; alert = $true
                config = [ordered]@{ type = 'aggregation-v1'; query = "$scope AND ($q)"; query_parameters = @(); streams = @(); group_by = $grp
                    series = @(@{ id = 'cnt'; type = 'count' })
                    conditions = @{ expression = @{ expr = '>='; left = @{ expr = 'number-ref'; ref = 'cnt' }; right = @{ expr = 'number'; value = $thr } } }
                    search_within_ms = $win * 60000; execute_every_ms = 60000; event_limit = 100 }
                field_spec = $fs; key_spec = $grp
                notification_settings = @{ grace_period_ms = 300000; backlog_size = 5 }
                notifications = @($(if ($notif) { @{ notification_id = $notif.id } }))
                storage = @(@{ type = 'persist-to-streams-v1'; streams = @('000000000000000000000002') })
            }
            try { $null = Invoke-NexusGraylog POST '/api/events/definitions?schedule=true' $body; Say FIX "탐지 규칙 $title" "$thr회/$win분, 묶음: $($grp -join ',')" }
            catch { Say FAIL "탐지 규칙 $title" $_.ErrorDetails.Message }
        }
        try { $since = (Invoke-NexusGraylog GET "/api/search/universal/relative?query=$([uri]::EscapeDataString($scope))&range=3600&limit=1&fields=src_ip,source").total_results
        Say $(if ($since -gt 0) { 'OK' } else { 'WARN' }) '최근 1시간 포털 로그 수신' "$since 건 $(if (-not $since) { '- 포털 서버(.14)에 GELF 전송 설정 필요(서버 적용 안내 참고)' })"
        } catch { Say INFO '최근 수신 건수 조회' 'Graylog 버전에 따라 미지원 - 검색 화면에서 _exists_:event_type 로 확인' }
        if ($SendTest -and $notif) { $null = Invoke-NexusGraylog POST "/api/events/notifications/$($notif.id)/test" $null; Say OK 'n8n 알림 시험 발송' 'Discord 확인' }
    } catch { Say FAIL 'Graylog API' ($_.ErrorDetails.Message + ' ' + $_.Exception.Message + ' @line ' + $_.InvocationInfo.ScriptLineNumber) }
    $H = $null
}

}
$out = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) ('docs\이시헌_환경점검_' + $(if ($FirewallOnly) { '방화벽_' } else { '' }) + (Get-Date -Format 'yyyyMMdd_HHmm') + '.txt')
$report | Set-Content -Path $out -Encoding UTF8
Write-Host "`n결과 저장: $out" -ForegroundColor White
Write-Host '창을 닫아도 됩니다.'; Start-Sleep -Seconds 5
