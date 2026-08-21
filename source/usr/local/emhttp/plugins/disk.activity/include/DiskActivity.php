<?PHP
$varroot = '/var/local/emhttp';
$activityIni = "$varroot/disk_activity.ini";
$disksIni = "$varroot/disks.ini";
header('Content-Type: application/json');
header('Cache-Control: no-store');
$activity = file_exists($activityIni) ? (@parse_ini_file($activityIni) ?: []) : [];
foreach ($activity as $dev => &$pct) $pct = max(0, min(100, intval($pct)));
unset($pct);
$result = [];
$disks = @parse_ini_file($disksIni, true);
if (is_array($disks)) {
  foreach ($disks as $section => $disk) {
    $dev = $disk['device'] ?? '';
    if ($dev !== '' && isset($activity[$dev])) $result[$section] = $activity[$dev];
  }
}
$result['_devices'] = $activity;
$cfg = [];
$defaultFile = dirname(__DIR__) . '/default.cfg';
$cfgFile = '/boot/config/plugins/disk.activity/disk.activity.cfg';
if (file_exists($defaultFile)) $cfg = @parse_ini_file($defaultFile) ?: [];
if (file_exists($cfgFile)) $cfg = array_merge($cfg, @parse_ini_file($cfgFile) ?: []);
$result['_config'] = ['display'=>$cfg['display'] ?? 'bar', 'window'=>$cfg['window'] ?? '2s'];
echo json_encode($result);
