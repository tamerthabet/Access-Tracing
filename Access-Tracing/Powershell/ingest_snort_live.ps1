# ===== Access Tracing - Live Snort Ingestion =====

$snortLog = "\\192.168.100.20\snort\AT_fast_alerts.log"
$checkpoint = "C:\MyProject\snort_checkpoint.txt"

$dbServer = "localhost"
$dbUser   = "app_user"
$dbPass   = "123"
$dbName   = "demo_app"

if (!(Test-Path $checkpoint)) {
    "0" | Out-File $checkpoint
}

$lastLine = Get-Content $checkpoint
$lines = Get-Content $snortLog

$newLines = $lines[$lastLine..($lines.Count - 1)]

foreach ($line in $newLines) {

    if ($line -match '^(\d+\/\d+-\d+:\d+:\d+\.\d+).*?\[\*\*\]\s(.+?)\s\[\*\*\].*?\{(\w+)\}\s([\d\.]+)\s->\s([\d\.]+)') {

        $timestamp = $matches[1]
        $message   = $matches[2]
        $protocol  = $matches[3]
        $srcIP     = $matches[4]
        $dstIP     = $matches[5]

        $sql = @"
INSERT INTO snort_alerts
(event_time, alert_message, protocol, source_ip, destination_ip)
VALUES
('$timestamp', '$message', '$protocol', '$srcIP', '$dstIP');
"@

        mysql -u$dbUser -p$dbPass $dbName -e $sql
    }
}

$lines.Count | Out-File $checkpoint
Write-Host "[+] Ingested $($newLines.Count) new alerts"
