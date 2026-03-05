<?php
// /api/export_audit.php
// Exports filtered audit rows to CSV (admin only).

declare(strict_types=1);
session_start();

require __DIR__ . '/../auth.php';
if (($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    exit;
}

$config = require __DIR__ . '/../config.php';
$mysqli = @new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) {
    http_response_code(500);
    exit('DB connect failed');
}
$mysqli->set_charset('utf8mb4');

// Inputs (same names as fetch_audit)
$qUser    = trim((string)($_GET['q_user']    ?? ''));
$qIp      = trim((string)($_GET['q_ip']      ?? ''));
$qResult  = trim((string)($_GET['q_result']  ?? 'all')); // success|fail|all
$dateFrom = trim((string)($_GET['date_from'] ?? ''));
$dateTo   = trim((string)($_GET['date_to']   ?? ''));

// WHERE builder
$where = [];
$params = [];
$types  = '';

if ($qUser !== '') { $where[]='username LIKE ?'; $params[]="%$qUser%"; $types.='s'; }
if ($qIp   !== '') { $where[]='ip_address LIKE ?'; $params[]="%$qIp%";  $types.='s'; }
if ($qResult === 'success') { $where[]='success=1'; }
elseif ($qResult === 'fail'){ $where[]='success=0'; }

if ($dateFrom !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateFrom)) {
    $where[] = 'DATE(created_at) >= ?'; $params[]=$dateFrom; $types.='s';
}
if ($dateTo !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateTo)) {
    $where[] = 'DATE(created_at) <= ?'; $params[]=$dateTo;   $types.='s';
}

$whereSql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$sql = "SELECT id, username, success, ip_address, user_agent, source, event_id, host, log_type, severity, ti_malicious, created_at
        FROM login_audit
        $whereSql
        ORDER BY created_at DESC";

$stmt = $mysqli->prepare($sql);
if ($types) { $stmt->bind_param($types, ...$params); }
$stmt->execute();
$res = $stmt->get_result();

$filename = 'audit_export_' . date('Ymd_His') . '.csv';
header('Content-Type: text/csv; charset=utf-8');
header("Content-Disposition: attachment; filename=\"$filename\"");

$out = fopen('php://output', 'w');
fputcsv($out, ['id','username','success','ip_address','user_agent','source','event_id','host','log_type','severity','ti_malicious','created_at']);

while ($row = $res->fetch_assoc()) {
    // Normalize booleans to 0/1
    $row['success'] = (int)$row['success'];
    $row['ti_malicious'] = (int)$row['ti_malicious'];
    fputcsv($out, $row);
}
fclose($out);
