# pfSense 규칙 — 공격망(Kali)에서는 포털만 접근하게

작성: 이시헌 · 2026-10-20

## 목표
공격망(VMnet2, Kali가 붙는 인터페이스, 예: `172.16.50.0/24`)에서 다른 네트워크는 전부 막고, 포털(`192.168.3.14:5070` 또는 `172.16.50.10:5070`)만 열어 둔다. 공격이 성공하더라도 공격망에서 Graylog·pfSense 관리 화면·DB(3307) 같은 내부 장비로 번지지 않게 하는 것이 목적이다.

**가장 중요:** 아래 3번처럼 **출발지 NAT를 걸지 않는다.** NAT를 걸면 모든 공격이 pfSense 주소 하나로 보여서 `src_ip` 기반 탐지(R1~R4)가 전부 무력화된다(03_팀_연동안내.md 확인 사항과 동일).

## 순서 (pfSense 웹 관리 화면)

1. **별칭(Alias) 만들기** — `Firewall → Aliases → Add`
   - 이름 `NEXUS_PORTAL`, 타입 Host(s), 주소에 포털 IP(`192.168.3.14` 및/또는 `172.16.50.10`) 추가.
2. **공격망 인터페이스 규칙** — `Firewall → Rules → (Kali가 붙은 인터페이스, 예: OPT1/공격망)`
   - 맨 위에 **허용** 규칙 추가: Protocol TCP, Source = 공격망 net, Destination = 별칭 `NEXUS_PORTAL`, Port 5070. Description: "공격망→포털 5070만 허용".
   - (선택, 이미 완료) 탐지용 로그를 보내야 하면 UDP 1514 → Graylog(`192.168.3.10`)도 같은 방식으로 허용 — Graylog 쪽 1514/udp syslog 입력은 이미 켜져 있다(10-20 환경 점검 결과).
   - 그 아래에 **차단** 규칙 추가: Source = 공격망 net, Destination = any. Description: "공격망→그 외 전부 차단". 로그(Log) 체크 — 막힌 시도도 기록되게.
   - 두 규칙의 순서가 중요하다(위에서부터 먼저 맞는 규칙 적용): 허용이 차단보다 위에 있어야 한다.
3. **NAT 확인** — `Firewall → NAT → Outbound`
   - 공격망 인터페이스에 대한 Outbound NAT(출발지 주소를 pfSense로 바꾸는 규칙)가 없는지 확인한다. Manual 모드라면 공격망→포털 트래픽에 해당하는 규칙이 없어야 한다. 있다면 "no NAT" 예외를 추가하거나 그 규칙을 지운다.
4. **저장 후 Apply Changes**, 그다음 Kali에서 확인:
   - 포털(`5070`)은 접속되고, pfSense 관리 화면(보통 443)이나 DB(3307) 같은 다른 포트는 응답이 없어야 한다(timeout).
   - 포털에서 `/no-such-page` 한 번 열어 `logs/security.jsonl`의 `not_found` 이벤트 `src_ip`가 **Kali 주소 그대로**인지 확인(NAT가 안 걸렸다는 증거).

## 자동화가 필요하면
포털 LAN 리다이렉트를 다루는 기존 `scripts/pfsense-local-team.php`와 같은 방식(백업 후 `config.xml` 수정 → `write_config` → `filter_configure()`)으로 위 별칭·규칙을 코드로 넣을 수도 있다. 수동으로 먼저 설정해 동작을 확인한 뒤, 반복 적용이 필요해지면 그때 스크립트로 옮기는 걸 권한다(pfSense 설정 파일을 코드로 직접 건드리는 작업이라 실수 시 영향이 크다).

## 이후
- 규칙을 넣은 뒤 `scripts/kali_breach_chain.py`(5단계 공격 체인 스크립트, 같은 폴더)로 공격망에서 포털까지만 닿는지, 그리고 AI 채팅방 공격 체인이 의도대로 막히는지/뚫리는지 확인한다.
