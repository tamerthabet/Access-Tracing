<?php
require __DIR__ . '/auth.php';

// === Access Control ===
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    http_response_code(401);
    echo "<div style='
        font-family:Segoe UI,Arial;
        background:#0d1117;
        color:#ff5555;
        text-align:center;
        padding:60px;
        font-size:18px;'>
        <h2>Unauthorized Access</h2>
        <p>You must log in as an admin to view this page.</p>
        <a href='login_form.html' style='color:#00b3ff;'>Return to Login</a>
    </div>";
    exit;
}

// === Database Connection ===
$config = require __DIR__ . '/config.php';
$mysqli = new mysqli($config['db_host'], $config['db_user'], $config['db_pass'], $config['db_name']);
if ($mysqli->connect_errno) {
    die("<h2 style='color:red;'>Database Connection Failed: " . htmlspecialchars($mysqli->connect_error) . "</h2>");
}
$mysqli->set_charset('utf8mb4');

// === Stats ===
$stat = $mysqli->query("
  SELECT
    COUNT(*) AS total,
    SUM(CASE WHEN success=1 THEN 1 ELSE 0 END) AS success_count,
    SUM(CASE WHEN success=0 THEN 1 ELSE 0 END) AS fail_count
  FROM login_audit
");
$stat = $stat ? $stat->fetch_assoc() : ['total'=>0,'success_count'=>0,'fail_count'=>0];
$total        = (int)($stat['total'] ?? 0);
$successCount = (int)($stat['success_count'] ?? 0);
$failCount    = (int)($stat['fail_count'] ?? 0);

// === Fetch Logs ===
$result = $mysqli->query("SELECT id, username, success, ip_address, source, event_id, host, severity, ti_malicious, created_at
                          FROM login_audit
                          WHERE username NOT IN ('SYSTEM', 'DefaultAppPool', 'IUSR')
                          AND username NOT LIKE 'WIN-%'
                          ORDER BY id DESC
                          LIMIT 100");
$rows = [];
if ($result) {
    while ($r = $result->fetch_assoc()) $rows[] = $r;
    $result->free();
}
$mysqli->close();

function esc($v) { return htmlspecialchars($v ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Access Tracing Admin | Tamer Thabet</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@2.7.3/dist/Chart.min.js"></script>
<style>
  body { font-family:"Segoe UI",Arial,sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:0; }
  header { background:linear-gradient(90deg,#0078d4,#00b3ff); color:white; padding:15px 25px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 2px 4px #00000055; }
  header h1 { margin:0; font-size:20px; font-weight:600; letter-spacing:0.5px; display:flex; align-items:center; gap:10px; }
  #clock { font-size:14px; opacity:0.9; margin-left:auto; }
  main { padding:20px; }
  h2 { color:#00b3ff; font-weight:600; }
  table { border-collapse:collapse; width:100%; margin-top:20px; background:#161b22; border:1px solid #30363d; }
  th,td { padding:8px 10px; border:1px solid #30363d; text-align:left; font-size:13px; }
  th { background:#1f2937; color:#7ee6ff; text-transform:uppercase; font-size:12px; letter-spacing:0.5px; }
  tr:nth-child(even){background:#11151a;} tr:hover{background:#1b2632;transition:0.2s;}
  .status-success{color:#00ff99;font-weight:bold;} .status-fail{color:#ff5555;font-weight:bold;}
  .badge-ti{color:#000;background:#ffcc00;border-radius:4px;padding:1px 5px;font-weight:bold;}
  footer{margin-top:25px;font-size:13px;color:#888;text-align:center;padding-bottom:15px;}
  #chartContainer{width:400px;margin:20px auto;background:#161b22;border-radius:10px;padding:15px;box-shadow:0 0 10px #00b3ff33;}
  .hint{text-align:center;color:#9aa6b2;margin-top:8px;font-size:13px;}
  .topbar-actions a{color:#fff;text-decoration:underline;margin-left:14px;font-weight:600;}
  .alert-badge{padding:3px 8px;border-radius:6px;font-size:13px;font-weight:bold;}
  .alert-active{background:#ff5555;color:white;}
  .alert-clear{background:#00cc66;color:white;}
</style>
</head>
<body>
  <header>
    <h1>Access Tracing Admin Panel Tamer Thabet <span id="alertBadge" class="alert-badge alert-clear"> CLEAR</span></h1>
    <div class="topbar-actions">
      <a href="seed_test_logs.php">Seed Logs</a>
      <a href="export_csv.php">Export CSV</a>
    </div>
    <div id="clock"></div>
  </header>

  <main>
    <p>Hello <b>Admin Tamer</b>, the system is live and monitoring access & Snort intrusion logs.</p>

    <!-- Access Chart -->
    <div id="chartContainer">
      <canvas id="loginChart"></canvas>
      <?php if ($total === 0): ?>
        <div class="hint">No logs yet — click <a href="seed_test_logs.php">Seed Logs</a> then refresh.</div>
      <?php endif; ?>
    </div>

    <!-- Snort Summary -->
    <div id="snortSummary" style="background:#161b22;margin-top:20px;border-radius:10px;padding:15px;text-align:center;box-shadow:0 0 10px #ffcc0033;">
      <h3 style="color:#ffcc00;">Snort Intrusion Activity</h3>
      <div id="alertCount" style="font-size:24px;font-weight:bold;color:#ff5555;">Loading...</div>
      <canvas id="snortChart" height="100" style="margin-top:15px;"></canvas>
      <div id="snortLastUpdate" style="color:#9aa6b2;font-size:12px;margin-top:5px;"></div>
    </div>

    <!-- Login Audit Table -->
    <table>
      <thead>
        <tr>
          <th>ID</th><th>User</th><th>Status</th><th>IP</th><th>Source</th>
          <th>Event ID</th><th>Host</th><th>Severity</th><th>Threat Intel</th><th>Time</th>
        </tr>
      </thead>
      <tbody>
        <?php if (empty($rows)): ?>
          <tr><td colspan="10" style="text-align:center;">No logs available</td></tr>
        <?php else: foreach ($rows as $r): ?>
          <tr>
            <td><?= esc($r['id']) ?></td>
            <td><?= esc($r['username']) ?></td>
            <td><?= ((int)$r['success'] === 1) ? '<span class="status-success">Success</span>' : '<span class="status-fail">Failed</span>' ?></td>
            <td><?= esc($r['ip_address']) ?></td>
            <td><?= esc($r['source']) ?></td>
            <td><?= esc($r['event_id']) ?></td>
            <td><?= esc($r['host']) ?></td>
            <td><?= esc($r['severity']) ?></td>
            <td><?= ((int)$r['ti_malicious'] === 1) ? '<span class="badge-ti">Malicious</span>' : '-' ?></td>
            <td><?= esc($r['created_at']) ?></td>
          </tr>
        <?php endforeach; endif; ?>
      </tbody>
    </table>

    <!-- Snort Intrusion Alerts -->
    <h2 style="color:#ffcc00;margin-top:40px;">Latest Snort Alerts</h2>
    <div id="snortAlertsContainer" style="background:#161b22;padding:15px;border-radius:10px;">
      <table id="snortTable" style="width:100%;border-collapse:collapse;">
        <thead><tr><th>Timestamp</th><th>Alert Text</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>

    <footer>
      Last refreshed at <?= date('H:i:s') ?> | Total logs: <?= $total ?> (<?= $successCount ?> success / <?= $failCount ?> fail)
    </footer>
  </main>

<script>
function updateClock(){
  var now = new Date();
  document.getElementById('clock').textContent = now.toLocaleDateString() + ' | ' + now.toLocaleTimeString();
}
updateClock();
setInterval(updateClock, 1000);

// === Login Chart ===
(function(){
  var dataSuccess = <?= $successCount ?>;
  var dataFail    = <?= $failCount ?>;
  if (dataSuccess === 0 && dataFail === 0) { dataSuccess = 1; dataFail = 0; }
  var ctx = document.getElementById('loginChart').getContext('2d');
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Success', 'Failed'],
      datasets: [{
        data: [dataSuccess, dataFail],
        backgroundColor: ['#00ff99', '#ff5555'],
        borderWidth: 0
      }]
    },
    options: { legend: { labels: { fontColor: '#e6edf3' } } }
  });
})();

// === Unified Snort Alerts Loader ===
async function refreshSnortData() {
  try {
    const res = await fetch('get_snort_alerts.php?cb=' + Date.now());
    const data = await res.json();

    // === Update counter ===
    document.getElementById('alertCount').textContent = data.length;
    document.getElementById('snortLastUpdate').textContent = "Last update: " + new Date().toLocaleTimeString();

    // === Badge status ===
    const badge = document.getElementById('alertBadge');
    if (data.length > 0) {
      badge.className = "alert-badge alert-active";
      badge.textContent = " ALERTS ACTIVE";
    } else {
      badge.className = "alert-badge alert-clear";
      badge.textContent = " CLEAR";
    }

    // === Table ===
    const tbody = document.querySelector('#snortTable tbody');
    tbody.innerHTML = data.slice(-20).reverse().map(a => {
      const color = a.AlertText.includes("ATTACK") ? "#ff5555" : "#00b3ff";
      return `<tr><td>${a.Timestamp}</td><td style="color:${color};">${a.AlertText}</td></tr>`;
    }).join('');

  } catch (e) {
    console.error("Snort fetch error:", e);
    document.getElementById('alertCount').textContent = "? Error loading data";
  }
}

// === Run initially and every 15s ===
refreshSnortData();
setInterval(refreshSnortData, 15000);
</script>
</body>
</html>
