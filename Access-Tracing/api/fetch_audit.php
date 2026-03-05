<?php
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../php_debug.log');

header('Content-Type: application/json');

echo "--- DEBUG START ---\n";

try {
    $config = require __DIR__ . '/../config.php';
    echo "Config loaded\n";

    $mysqli = new mysqli(
        $config['db_host'],
        $config['db_user'],
        $config['db_pass'],
        $config['db_name']
    );
    echo "DB connected\n";

    if ($mysqli->connect_errno) {
        throw new Exception("DB connect failed: " . $mysqli->connect_error);
    }

    $result = $mysqli->query("SELECT COUNT(*) AS total FROM login_audit");
    if (!$result) {
        throw new Exception("Query failed: " . $mysqli->error);
    }

    $count = $result->fetch_assoc()['total'];
    echo "Total rows in login_audit: $count\n";

    echo json_encode(["status" => "ok", "rows" => $count]);
} catch (Throwable $e) {
    echo "Error: " . $e->getMessage();
}
?>
