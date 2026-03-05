<?php
require __DIR__ . '/auth.php';
if (($_SESSION['role'] ?? '') !== 'admin') { http_response_code(401); exit('Unauthorized'); }

$config = require __DIR__ . '/config.php';
$mysqli = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) { http_response_code(500); exit('DB error'); }
$mysqli->set_charset('utf8mb4');

$sql = "SELECT id, username, success, ip_address, source, event_id, host, severity, ti_malicious, created_at
        FROM login_audit ORDER BY id DESC LIMIT 100";
$res = $mysqli->query($sql);

header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename=login_audit_last100.csv');

$out = fopen('php://output', 'w');
fputcsv($out, ['id','username','success','ip_address','source','event_id','host','severity','ti_malicious','created_at']);
if ($res) {
    while ($r = $res->fetch_assoc()) {
        $r['success'] = (int)$r['success'];
        $r['ti_malicious'] = (int)$r['ti_malicious'];
        fputcsv($out, $r);
    }
    $res->free();
}
fclose($out);
$mysqli->close();
