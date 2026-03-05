<?php
$file = 'C:\\MyProject\\api\\test_write.txt';
file_put_contents($file, "PHP can write this!\n", FILE_APPEND);
echo "Done!";
?>
