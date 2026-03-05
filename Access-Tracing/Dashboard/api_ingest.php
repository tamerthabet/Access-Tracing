<?php
// ========================================================
// API Ingestion Endpoint for PowerShell & Snort (Tamer Thabet)
// MUST BE PROTECTED BY A SECRET KEY
// ========================================================

// --- Configuration ---
$config = require __DIR__ . '/config.php';
// !!! IMPORTANT: CHANGE THIS TO A STRONG SECRET KEY !!!
$API_SECRET = 'c6e9f1a2b0d3e5f8a7b9c0d1e2f3a4b5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'; // <-- KEY

// --- 1. Security Check ---
// We check for the secret key in a custom HTTP header (X-API-Key)
if (($_SERVER['HTTP_X_API_KEY'] ?? '') !== $API_SECRET) {
    http_response_code(401);
    die('Unauthorized API Key.');
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Method Not Allowed.');
}

// --- 2. Database Connection ---
$mysqli = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) {
    http_response_code(500);
    error_log("API DB connect error: " . $mysqli->connect_error);
    die("Database error.");
}

// --- 3. Process Data ---
$json_data = file_get_contents('php://input');
$log_data = json_decode($json_data, true);

if (empty($log_data) || !is_array($log_data)) {
    http_response_code(400);
    die('Invalid JSON input.');
}

// --- 4. Prepare Fields & Insert (Matching login_audit table) ---
// Default values are set if PowerShell doesn't send them
$username   = $log_data['username'] ?? 'SYSTEM_EVENT';
$success    = $log_data['success'] ?? 0;
$ip_address = $log_data['ip_address'] ?? '127.0.0.1';
$source     = $log_data['source'] ?? 'system'; // 'system' or 'network'
$event_id   = $log_data['event_id'] ?? NULL;
$host       = $log_data['host'] ?? 'WindowsServer';
$severity   = $log_data['severity'] ?? 'info';
$log_type   = $log_data['log_type'] ?? 'security';
$user_agent = $log_data['user_agent'] ?? 'PowerShell-Script';

$stmt = $mysqli->prepare("
    INSERT INTO login_audit (username, success, ip_address, user_agent, source, event_id, host, log_type, severity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
");
$stmt->bind_param('sisssisss', $username, $success, $ip_address, $user_agent, $source, $event_id, $host, $log_type, $severity);

if ($stmt->execute()) {
    http_response_code(200);
    echo "Log entry created successfully.";
} else {
    http_response_code(500);
    error_log("DB execution error: " . $stmt->error);
    echo "Log insertion failed.";
}

$stmt->close();
$mysqli->close();
?>