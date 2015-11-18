<?php
require "Transaction.php";
require "Database.php";

// container for HTTP Request/Response
$trans = new \Griffin\Transaction();
$trans->dispatch();
$trans->respond();
?>
