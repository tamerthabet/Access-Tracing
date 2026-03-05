$sourceUrl = "http://192.168.100.20/snort_alerts.csv"
$localFile = "C:\MyProject\snort_alerts.csv"

Write-Host "=== Access Tracing Snort Listener Started ==="
Write-Host "Fetching every 30 seconds. Press Ctrl + C to stop.`n"

while ($true) {
    try {
        $data = Invoke-WebRequest -Uri $sourceUrl -UseBasicParsing -TimeoutSec 5

        if ($data.StatusCode -eq 200 -and $data.Content.Length -gt 20) {
            $data.Content | Out-File -FilePath $localFile -Encoding UTF8
            Write-Host "[+] Alerts updated at $(Get-Date)"
        } else {
            Write-Host "[!] No alerts returned."
        }
    } catch {
        Write-Host "[ERROR] Cannot fetch alerts."
    }

    Start-Sleep -Seconds 30
}
