<?php
// ========================================================
// login.php — Intelligent Secure Login (by Tamer Thabet)
// ========================================================

session_save_path('C:\\MyProject\\sessions');
$config = require __DIR__ . '/config.php';

// --- Connect to Database ---
$mysqli = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) {
    error_log("DB connect error: " . $mysqli->connect_error);
    http_response_code(500);
    echo "Database connection failed.";
    exit;
}

// --- Ensure login_audit table exists ---
$mysqli->query("
CREATE TABLE IF NOT EXISTS login_audit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    success TINYINT(1),
    ip_address VARCHAR(45),
    user_agent TEXT,
    source VARCHAR(20) DEFAULT 'web',
    event_id VARCHAR(32) DEFAULT NULL,
    host VARCHAR(100) DEFAULT NULL,
    log_type VARCHAR(50) DEFAULT NULL,
    severity VARCHAR(20) DEFAULT NULL,
    ti_malicious TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
");

// --- Start session ---
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// --- Collect Data ---
$username = trim($_POST['username'] ?? '');
$password = $_POST['password'] ?? '';

// Fix: Standardize IPv6 loopback (::1) to IPv4 loopback (127.0.0.1)
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if ($ip === '::1' || $ip === ':1') { // Check for both common IPv6 loopbacks
    $ip = '127.0.0.1';
}

$ua = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$source = 'web';
$success = 0;
// ... rest of code
// --- Validate Input ---
if ($username === '' || $password === '') {
    echo "Please enter username and password.";
    exit;
}

// --- Check for lockout (too many fails) ---
$lockCheck = $mysqli->prepare("
    SELECT COUNT(*) FROM login_audit
    WHERE username=? AND success=0 AND created_at > NOW() - INTERVAL 1 MINUTE
");
$lockCheck->bind_param('s', $username);
$lockCheck->execute();
$lockCheck->bind_result($failCount);
$lockCheck->fetch();
$lockCheck->close();

if ($failCount >= 5) {
    echo "Account temporarily locked due to multiple failed attempts. Try again in 1 minute.";
    $stmt = $mysqli->prepare("INSERT INTO login_audit (username, success, ip_address, user_agent, source, severity) VALUES (?, 0, ?, ?, 'web', 'warning')");
    $stmt->bind_param('sss', $username, $ip, $ua);
    $stmt->execute();
    $stmt->close();
    exit;
}

// --- Verify user credentials ---
$stmt = $mysqli->prepare("SELECT id, username, password_hash, display_name, role FROM users WHERE username=? LIMIT 1");
$stmt->bind_param('s', $username);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if ($user && password_verify($password, $user['password_hash'])) {
    $success = 1;
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['display_name'] = $user['display_name'];
    $_SESSION['role'] = $user['role'];
    $severity = 'info';
    echo "? Login successful! Welcome, " . htmlspecialchars($user['display_name'] ?? $user['username']);
} else {
    $success = 0;
    $severity = 'high';
    echo "? Login failed.";
}

// --- Insert into audit log ---
$stmt = $mysqli->prepare("
INSERT INTO login_audit (username, success, ip_address, user_agent, source, severity)
VALUES (?, ?, ?, ?, ?, ?)
");
$stmt->bind_param('sissss', $username, $success, $ip, $ua, $source, $severity);
$stmt->execute();
$stmt->close();

$mysqli->close();

// --- Redirect on success ---
if ($success === 1) {
    header("Refresh: 1; URL=admin_audit.php");
    exit;
}
?>
