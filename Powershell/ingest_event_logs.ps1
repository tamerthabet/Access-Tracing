# =================================================================
# PowerShell Script: Event Viewer Log Ingestion (Tamer Thabet)
# FIX: Using robust XML Filter for maximum compatibility.
# =================================================================

# --- 1. CONFIGURATION ---
$API_KEY = 'c6e9f1a2b0d3e5f8a7b9c0d1e2f3a4b5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0' # <<< CHECK THIS KEY!
$API_URL = 'http://localhost/api_ingest.php' 
$COMPUTER_NAME = $env:COMPUTERNAME
$LOG_SOURCE = 'system'

# Security Event IDs we care about (Logon Success/Failure)
$EventIDs = @(4624, 4625)

# Path to a file that tracks the last processed log entry ID
$CheckpointFile = "C:\MyProject\log_checkpoint.txt"

# --- 2. CHECKPOINT: Get Last Processed ID ---
if (Test-Path $CheckpointFile) {
    $LastID = Get-Content $CheckpointFile | Select-Object -First 1
    if ($LastID -match '^\d+$') {
        Write-Host "Found checkpoint ID: $LastID"
    } else {
        $LastID = 0
        Write-Warning "Checkpoint file contents invalid. Starting from 0."
    }
} else {
    $LastID = 0
    Write-Host "No checkpoint file found. Starting from oldest logs."
}

# --- 3. FETCH NEW EVENT LOGS (XML FILTER) ---
Write-Host "Fetching new Security events (IDs 4624, 4625) newer than record ID $LastID..."

# Build the XPath query string
$EventIDQuery = ($EventIDs | ForEach-Object { "EventID=$_" }) -join ' or '
$XPath = "*/System[($EventIDQuery) and (EventRecordID > $LastID)]"

# Define the log query using the XML filter method
$Filter = @{
    LogName = 'Security'
    XPath   = $XPath
}

try {
    # Get logs using the XML Filter. Use Get-Date.AddDays(-7) to restrict search window for efficiency.
    $Events = Get-WinEvent -FilterXml ([xml]"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>$XPath</Select></Query></QueryList>") | 
              Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) } |
              Sort-Object -Property RecordId

} catch {
    Write-Error "Error fetching Event Logs: $($_.Exception.Message)"
    exit 1
}

if ($Events.Count -eq 0) {
    Write-Host "No new events to ingest."
    exit
}

# --- 4. PROCESS AND INGEST EVENTS ---
$Batch = @()
$CurrentMaxID = $LastID
Write-Host "Processing $($Events.Count) new events..."

foreach ($Event in $Events) {
    # Extract the relevant data from the event details
    $EventData = @{
        'source'     = $LOG_SOURCE
        'host'       = $COMPUTER_NAME
        'event_id'   = $Event.ID
        'log_type'   = $Event.LogName

        'username'   = 'N/A'
        'ip_address' = 'N/A'
        'success'    = 0
        'severity'   = 'info'
    }

    # Extracting Specific Logon Data
    if ($Event.ID -eq 4624) { # Success
        $EventData.success = 1
        $EventData.severity = 'info'
        $EventData.username = ($Event.Properties[5].Value -replace '.*\\', '' )
        $EventData.ip_address = $Event.Properties[18].Value
    } elseif ($Event.ID -eq 4625) { # Failure
        $EventData.success = 0
        $EventData.severity = 'critical'
        $EventData.username = ($Event.Properties[5].Value -replace '.*\\', '' )
        $EventData.ip_address = $Event.Properties[19].Value
    }

    # Ensure IP is not a local loopback (::1, -)
    if ($EventData.ip_address -eq '-' -or $EventData.ip_address -eq '::1' -or $EventData.ip_address -eq '127.0.0.1') {
        $EventData.ip_address = '127.0.0.1' 
    }

    # Convert to JSON and send to API
    $JsonPayload = $EventData | ConvertTo-Json -Compress

    try {
        $Response = Invoke-RestMethod -Uri $API_URL -Method Post -Body $JsonPayload -ContentType 'application/json' -Headers @{'X-API-Key' = $API_KEY}
        
        if ($Response -eq "Log entry created successfully.") {
            Write-Host "ID $($Event.RecordId) ingested successfully."
            $CurrentMaxID = $Event.RecordId 
        } else {
            Write-Error "API failed for ID $($Event.RecordId). Response: $Response"
            break 
        }
        
    } catch {
        Write-Error "REST call failed: $($_.Exception.Message)"
        break
    }
}

# --- 5. UPDATE CHECKPOINT ---
if ($CurrentMaxID -gt $LastID) {
    $CurrentMaxID | Out-File $CheckpointFile -Force
    Write-Host "Checkpoint updated to Record ID: $CurrentMaxID"
}