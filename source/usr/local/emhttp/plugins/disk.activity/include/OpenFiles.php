<?PHP
header('Content-Type: application/json');
header('Cache-Control: no-store');
$file = '/var/local/emhttp/disk_open_files.json';
$limit = isset($_GET['limit']) ? intval($_GET['limit']) : 12;
$limit = max(1, min(500, $limit));
$data = null;
if (is_readable($file)) $data = json_decode(@file_get_contents($file), true);
if (!is_array($data)) $data = ['updated'=>0, 'enabled'=>true, 'truncated'=>false, 'files'=>[]];
$updated = intval($data['updated'] ?? 0);
$data['stale'] = !$updated || ((int)round(microtime(true)*1000) - $updated > 20000);
$files = is_array($data['files'] ?? null) ? $data['files'] : [];
$data['total'] = count($files);
$data['files'] = array_slice($files, 0, $limit);
echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
