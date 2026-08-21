<?PHP
header('Content-Type: application/json');
header('Cache-Control: no-store');

function fail_json(int $status, string $message) {
    http_response_code($status);
    echo json_encode(['ok' => false, 'error' => $message]);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail_json(405, 'POST required');
}

$action = (string)($_POST['action'] ?? '');
if ($action !== 'reset_history') {
    fail_json(400, 'Unknown action');
}

$historyFile = '/boot/config/plugins/disk.activity/wake-history.jsonl';
$lockFile = '/var/lock/disk_activity_plus_history.lock';
$cacheFile = '/var/local/emhttp/disk_wake_history_cache.json';

$lock = @fopen($lockFile, 'c+');
if (!$lock) {
    fail_json(500, 'Unable to open history lock');
}
if (!@flock($lock, LOCK_EX)) {
    fclose($lock);
    fail_json(500, 'Unable to lock history');
}

$dir = dirname($historyFile);
if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
    @flock($lock, LOCK_UN);
    fclose($lock);
    fail_json(500, 'Unable to create history directory');
}

$tmp = $historyFile . '.reset.' . getmypid();
$ok = @file_put_contents($tmp, '') !== false && @rename($tmp, $historyFile);
if (!$ok) {
    @unlink($tmp);
    @flock($lock, LOCK_UN);
    fclose($lock);
    fail_json(500, 'Unable to reset history');
}

@unlink($cacheFile);
@unlink($cacheFile . '.tmp');
@flock($lock, LOCK_UN);
fclose($lock);

echo json_encode(['ok' => true]);
