<?php
// =======================================================
// get_snort_alerts.php
// Tamer Thabet - Clean, deduped Snort feed for dashboard
// =======================================================

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, must-revalidate');
error_reporting(0);

// 1) Where to read Snort alerts from (Kali CSV)
$csvUrl = 'http://192.168.100.20/snort_alerts.csv';

// 2) How many alerts max to send to the dashboard
$MAX_ALERTS = 100;

// 3) Load CSV from Kali
$data = @file_get_contents($csvUrl);
if ($data === false || trim($data) === '') {
    echo json_encode(["error" => "Failed to load CSV"], JSON_PRETTY_PRINT);
    exit;
}

// 4) Split into lines
$lines = preg_split('/\r\n|\n|\r/', trim($data));

// 5) Walk from bottom (newest) ? up, dedupe & limit
$rows = [];
$seen = [];

for ($i = count($lines) - 1; $i >= 0; $i--) {
    $line = trim($lines[$i]);
    if ($line === '') continue;

    // skip header or junk
    if (stripos($line, 'Timestamp') === 0) continue;
    if (stripos($line, 'status') === 0) continue;

    $parts = str_getcsv($line);
    if (count($parts) < 2) continue;

    $ts   = trim($parts[0]);
    $text = trim($parts[1]);

    if ($text === '' || strlen($text) < 5) continue;

    // 6) Dedup key: same second + same message = one alert
    // Example ts: "11/20-09:32:10.801847" ? "11/20-09:32:10"
    $tsShort = substr($ts, 0, 17);
    $key = $tsShort . '|' . $text;

    if (isset($seen[$key])) {
        continue; // already counted this "type" of alert at that second
    }
    $seen[$key] = true;

    $rows[] = [
        'Timestamp' => $ts,
        'AlertText' => $text
    ];

    if (count($rows) >= $MAX_ALERTS) {
        break;
    }
}

// 7) Put back into chronological order (oldest ? newest)
$rows = array_reverse($rows);

// 8) Output clean JSON array
if (ob_get_length()) {
    ob_clean();
}
echo json_encode($rows, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
exit;
