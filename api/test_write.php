<?php
$path = __DIR__ . '/debug_test.txt';
file_put_contents($path, "? Write test at " . date('H:i:s') . "\n", FILE_APPEND);
echo "Check if debug_test.txt was created.";
