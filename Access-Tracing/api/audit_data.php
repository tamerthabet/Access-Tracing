<?php
require __DIR__ . '/../auth.php';
if (($_SESSION['role'] ?? '') !== 'admin') {
    http_response_code(403);
    exit(json_encode(['error' => 'unauthorized']));
}

$config = require __DIR__ . '/../config.php';
$mysqli = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) {
    http_response_code(500);
    exit(json_encode(['error' => 'dbfail']));
}

$result = $mysqli->query("SELECT id, username, success, ip_address, source, event_id, host, severity, ti_malicious, created_at
                          FROM login_audit ORDER BY id DESC LIMIT 100");
$rows = [];
$success = 0;
$fail = 0;
while ($r = $result->fetch_assoc()) {
    $r['success'] = (int)$r['success'];
    if ($r['success'] === 1) $success++; else $fail++;
    $rows[] = $r;
}
$mysqli->close();

header('Content-Type: application/json');
echo json_encode(['rows' => $rows, 'success' => $success, 'fail' => $fail]);
