<?PHP
header('Content-Type: application/json');
header('Cache-Control: no-store');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { http_response_code(405); echo json_encode(['ok'=>false,'error'=>'POST required']); exit; }
$action = $_POST['action'] ?? '';
if ($action !== 'reset_history') { http_response_code(400); echo json_encode(['ok'=>false,'error'=>'Unknown action']); exit; }
$historyFile = '/boot/config/plugins/disk.activity/wake-history.jsonl';
$cacheFile = '/var/local/emhttp/disk_wake_history_cache.json';
$fp = @fopen($historyFile, 'c+');
if (!$fp) { http_response_code(500); echo json_encode(['ok'=>false,'error'=>'Unable to open history']); exit; }
if (!@flock($fp, LOCK_EX)) { fclose($fp); http_response_code(500); echo json_encode(['ok'=>false,'error'=>'Unable to lock history']); exit; }
@ftruncate($fp, 0); @fflush($fp); @flock($fp, LOCK_UN); fclose($fp);
@unlink($cacheFile); @unlink($cacheFile.'.tmp');
echo json_encode(['ok'=>true]);
