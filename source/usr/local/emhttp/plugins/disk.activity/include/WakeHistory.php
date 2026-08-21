<?PHP
/* Disk Activity - Wake History JSON API
 * GPLv2
 */
header('Content-Type: application/json');
header('Cache-Control: no-store');

$historyFile = '/boot/config/plugins/disk.activity/wake-history.jsonl';
$stateFile   = '/var/local/emhttp/disk_wake_state.json';
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 300;
$limit = max(1, min(2000, $limit));
$nowMs = (int)round(microtime(true) * 1000);
$dayMs = 86400000;

$events = [];
$all = [];
if (is_readable($historyFile)) {
    $lines = @file($historyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    foreach ($lines as $line) {
        $e = json_decode($line, true);
        if (!is_array($e) || empty($e['ts'])) continue;
        $all[] = $e;
    }
}

usort($all, function($a, $b) { return ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0); });
$events = array_slice($all, 0, $limit);

$disks = [];
$actors = [];
$sources = [];
$total7d = 0;
foreach ($all as $e) {
    $ts = intval($e['ts'] ?? 0);
    $age = $nowMs - $ts;
    $disk = (string)($e['disk'] ?? $e['device'] ?? 'unknown');
    $actor = trim((string)($e['container'] ?? ''));
    if ($actor === '') $actor = trim((string)($e['process'] ?? 'unknown'));
    if ($actor === '') $actor = 'unknown';

    if (!isset($sources[$actor])) {
        $sources[$actor] = [
            'source' => $actor,
            'count24h' => 0,
            'count7d' => 0,
            'avg7d' => 0,
            'share7d' => 0,
            'last_ts' => 0,
            'disks' => [],
        ];
    }
    if ($ts > $sources[$actor]['last_ts']) $sources[$actor]['last_ts'] = $ts;
    $sources[$actor]['disks'][$disk] = true;
    if ($age >= 0 && $age <= $dayMs) $sources[$actor]['count24h']++;
    if ($age >= 0 && $age <= 7 * $dayMs) {
        $sources[$actor]['count7d']++;
        $total7d++;
    }

    if (!isset($disks[$disk])) {
        $disks[$disk] = [
            'device' => $e['device'] ?? '',
            'last_ts' => 0,
            'last_actor' => '',
            'last_path' => '',
            'count24h' => 0,
            'count7d' => 0,
            'avg7d' => 0,
            'actors7d' => [],
        ];
    }
    $d =& $disks[$disk];
    if ($ts > $d['last_ts']) {
        $d['last_ts'] = $ts;
        $d['last_actor'] = $actor;
        $d['last_path'] = $e['path'] ?? '';
        $d['last_confidence'] = $e['confidence'] ?? 'unknown';
    }
    if ($age >= 0 && $age <= $dayMs) $d['count24h']++;
    if ($age >= 0 && $age <= 7 * $dayMs) {
        $d['count7d']++;
        $d['actors7d'][$actor] = ($d['actors7d'][$actor] ?? 0) + 1;
        $actors[$actor] = ($actors[$actor] ?? 0) + 1;
    }
    unset($d);
}

foreach ($disks as &$d) {
    $d['avg7d'] = round($d['count7d'] / 7, 2);
    arsort($d['actors7d']);
    $top = key($d['actors7d']);
    $topCount = $top !== null ? intval(current($d['actors7d'])) : 0;
    $d['top_actor'] = $top ?: '';
    $d['top_share'] = $d['count7d'] > 0 ? round($topCount * 100 / $d['count7d'], 1) : 0;
}
unset($d);
arsort($actors);

$sourceList = [];
foreach ($sources as $src) {
    $src['avg7d'] = round($src['count7d'] / 7, 2);
    $src['share7d'] = $total7d > 0 ? round($src['count7d'] * 100 / $total7d, 1) : 0;
    $src['disks'] = array_keys($src['disks']);
    sort($src['disks']);
    $sourceList[] = $src;
}
usort($sourceList, function($a, $b) {
    $byCount = ($b['count7d'] ?? 0) <=> ($a['count7d'] ?? 0);
    if ($byCount !== 0) return $byCount;
    return ($b['last_ts'] ?? 0) <=> ($a['last_ts'] ?? 0);
});

$state = null;
if (is_readable($stateFile)) {
    $state = json_decode(@file_get_contents($stateFile), true);
    if (!is_array($state)) $state = null;
}

echo json_encode([
    'events' => $events,
    'disks' => $disks,
    'actors7d' => $actors,
    'sources' => $sourceList,
    'state' => $state,
    'total' => count($all),
    'now' => $nowMs,
], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
