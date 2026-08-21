<?PHP
header('Content-Type: application/json');
header('Cache-Control: no-store');

$historyFile = '/boot/config/plugins/disk.activity/wake-history.jsonl';
$stateFile = '/var/local/emhttp/disk_wake_state.json';
$cacheFile = '/var/local/emhttp/disk_wake_history_cache.json';
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 300;
$limit = max(1, min(2000, $limit));
$nowMs = (int)round(microtime(true) * 1000);
$dayMs = 86400000;
$stat = @stat($historyFile);
$sig = ($stat ? ($stat['size'].'|'.$stat['mtime']) : '0|0');

$cached = null;
if (is_readable($cacheFile)) {
    $cached = json_decode(@file_get_contents($cacheFile), true);
    if (!is_array($cached) || ($cached['_sig'] ?? '') !== $sig || ($cached['_limit'] ?? 0) !== $limit) $cached = null;
}
if ($cached) {
    unset($cached['_sig'], $cached['_limit']);
    $cached['now'] = $nowMs;
    echo json_encode($cached, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

$eventsRing = [];
$disks = [];
$sources = [];
$total = 0;
$total7d = 0;
$confirmed7d = 0;

$fp = @fopen($historyFile, 'r');
if ($fp) {
    @flock($fp, LOCK_SH);
    while (($line = fgets($fp)) !== false) {
        $e = json_decode($line, true);
        if (!is_array($e) || empty($e['ts'])) continue;
        $total++;
        $eventsRing[] = $e;
        if (count($eventsRing) > $limit) array_shift($eventsRing);

        $ts = intval($e['ts']);
        $age = $nowMs - $ts;
        $disk = (string)($e['disk'] ?? $e['device'] ?? 'unknown');
        $confidence = strtolower((string)($e['confidence'] ?? 'unknown'));
        $candidateActor = trim((string)($e['container'] ?? ''));
        if ($candidateActor === '') $candidateActor = trim((string)($e['process'] ?? 'unknown'));
        if ($candidateActor === '') $candidateActor = 'unknown';
        // Only HIGH events are credited to a source. MEDIUM stays visible in event history
        // as a possible process but is grouped as unknown for source/share statistics.
        $actor = $confidence === 'high' ? $candidateActor : 'unknown';

        if (!isset($sources[$actor])) $sources[$actor] = ['source'=>$actor,'count24h'=>0,'count7d'=>0,'last_ts'=>0,'disks'=>[]];
        if ($ts > $sources[$actor]['last_ts']) $sources[$actor]['last_ts'] = $ts;
        $sources[$actor]['disks'][$disk] = true;
        if ($age >= 0 && $age <= $dayMs) $sources[$actor]['count24h']++;
        if ($age >= 0 && $age <= 7*$dayMs) {
            $sources[$actor]['count7d']++;
            $total7d++;
            if ($confidence === 'high') $confirmed7d++;
        }

        if (!isset($disks[$disk])) $disks[$disk] = [
            'device'=>$e['device'] ?? '', 'last_ts'=>0, 'last_path'=>'', 'count24h'=>0, 'count7d'=>0, 'actors7d'=>[]
        ];
        $d =& $disks[$disk];
        if ($ts > $d['last_ts']) {
            $d['last_ts'] = $ts;
            $d['last_path'] = $e['path'] ?? '';
            $d['last_confidence'] = $confidence;
        }
        if ($age >= 0 && $age <= $dayMs) $d['count24h']++;
        if ($age >= 0 && $age <= 7*$dayMs) {
            $d['count7d']++;
            $d['actors7d'][$actor] = ($d['actors7d'][$actor] ?? 0) + 1;
        }
        unset($d);
    }
    @flock($fp, LOCK_UN);
    fclose($fp);
}

foreach ($disks as &$d) {
    $d['avg7d'] = round($d['count7d']/7, 2);
    arsort($d['actors7d']);
    $top = key($d['actors7d']);
    $topCount = $top !== null ? intval(current($d['actors7d'])) : 0;
    $d['top_actor'] = $top ?: '';
    $d['top_share'] = $d['count7d'] ? round($topCount*100/$d['count7d'], 1) : 0;
}
unset($d);

$sourceList = [];
foreach ($sources as $src) {
    $src['avg7d'] = round($src['count7d']/7, 2);
    $src['share7d'] = $total7d ? round($src['count7d']*100/$total7d, 1) : 0;
    $src['disks'] = array_keys($src['disks']); sort($src['disks']);
    $sourceList[] = $src;
}
usort($sourceList, function($a,$b){
    $c = ($b['count7d']??0) <=> ($a['count7d']??0);
    return $c ?: (($b['last_ts']??0) <=> ($a['last_ts']??0));
});

$state = null;
if (is_readable($stateFile)) {
    $state = json_decode(@file_get_contents($stateFile), true);
    if (!is_array($state)) $state = null;
}

$result = [
    'events'=>array_reverse($eventsRing),
    'disks'=>$disks,
    'sources'=>$sourceList,
    'state'=>$state,
    'total'=>$total,
    'total7d'=>$total7d,
    'confirmed7d'=>$confirmed7d,
    'confirmed_share7d'=>$total7d ? round($confirmed7d*100/$total7d,1) : 0,
    'now'=>$nowMs,
];
$toCache = $result; $toCache['_sig']=$sig; $toCache['_limit']=$limit;
@file_put_contents($cacheFile.'.tmp', json_encode($toCache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), LOCK_EX);
@rename($cacheFile.'.tmp', $cacheFile);
echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
