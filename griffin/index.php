<?php
require "Transaction.php";

// container for HTTP Request/Response
$trans = new \Griffin\Transaction();
$trans->dispatch();
$trans->respond();
?>
