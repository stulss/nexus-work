<?php
require_once('/etc/inc/config.inc');
require_once('/etc/inc/filter.inc');
if (($config['interfaces']['lan']['ipaddr'] ?? '') !== '172.16.50.2') exit(1);
$backup='/conf/config.xml.before-nexus-local-'.date('Ymd-His');
if (!copy('/conf/config.xml',$backup)) exit(2);
chmod($backup,0600);
$found=false;
foreach ($config['nat']['rule'] as &$r) {
    if (($r['descr'] ?? '') === 'NEXUS WORK team portal LAN 5070') {
        if (!in_array($r['target'],['192.168.3.14','192.168.3.10'])) exit(3);
        $r['target']='192.168.3.10';
        // Evaluate filter rules after translation, instead of rdr pass bypass.
        unset($r['associated-rule-id']);
        $found=true;
    }
}
unset($r);
if (!$found) exit(4);
$hasAlias=false;
foreach (($config['aliases']['alias'] ?? []) as $a) {
    if ($a['name']==='NEXUS_AUTO_BLOCK') {
        if (($a['descr'] ?? '')!=='NEXUS automation test targets') exit(5);
        $hasAlias=true;
    }
}
if (!$hasAlias) $config['aliases']['alias'][]=[
    'name'=>'NEXUS_AUTO_BLOCK','type'=>'host','address'=>'198.51.100.254',
    'descr'=>'NEXUS automation test targets','detail'=>'Reserved placeholder'
];
$hasRule=false;
foreach (($config['filter']['rule'] ?? []) as $r)
    if (($r['descr'] ?? '')==='NEXUS automated block list') $hasRule=true;
if (!$hasRule) array_unshift($config['filter']['rule'],[
    'type'=>'block','interface'=>'lan','ipprotocol'=>'inet',
    'source'=>['address'=>'NEXUS_AUTO_BLOCK'],'destination'=>['any'=>''],
    'log'=>'','descr'=>'NEXUS automated block list','tracker'=>'1792395001'
]);
write_config('NEXUS local team portal and controlled auto-block table');
$result=filter_configure();
echo json_encode(['backup'=>$backup,'filter_result'=>$result])."\n";
