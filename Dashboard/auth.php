<?php
// auth.php — handles session safely
if (session_status() === PHP_SESSION_NONE) {
    $sessPath = 'C:\\MyProject\\sessions';
    if (!is_dir($sessPath)) {
        mkdir($sessPath, 0777, true);
    }
    ini_set('session.save_path', $sessPath);
    session_start();
}

// ?? Check if user is logged in at all
if (!isset($_SESSION['username'])) {
    http_response_code(401);
    echo "<div style='
        font-family:Segoe UI,Arial;
        background:#0d1117;
        color:#ff5555;
        text-align:center;
        padding:60px;
        font-size:18px;'>
        <h2>Unauthorized Access</h2>
        <p>You must log in to view this page.</p>
        <a href='/login_form.html' style='color:#00b3ff;'>Return to Login</a>
    </div>";
    exit;
}

// ?? If this page requires admin access
if (isset($require_admin) && $require_admin === true) {
    if (($_SESSION['role'] ?? '') !== 'admin') {
        http_response_code(403);
        echo "<div style='
            font-family:Segoe UI,Arial;
            background:#0d1117;
            color:#ffcc00;
            text-align:center;
            padding:60px;
            font-size:18px;'>
            <h2>Access Denied</h2>
            <p>This section is for administrators only.</p>
            <a href='/login_form.html' style='color:#00b3ff;'>Return to Login</a>
        </div>";
        exit;
    }
}
?>
