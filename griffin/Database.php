<?php
require "config.php";

$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASSWORD);

if ($mysqli->connect_errno) {
    // TODO these DB errors need to happen in a standard way
    die("Failed to connect to MySQL: (" . $mysqli->connect_errno . ") " .
        $mysqli->connect_error);
}

// make sure our database exists
if (!$mysqli->query("CREATE DATABASE IF NOT EXISTS " . DB_NAME .
                    " DEFAULT CHARACTER SET utf8")) {
    die("Failed to create database: " . DB_NAME);
}

if (!$mysqli->select_db(DB_NAME)) {
    die("Failed to select database: " . DB_NAME);
}

// create tables
$query = "CREATE TABLE IF NOT EXISTS `record` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `user_id` integer NOT NULL,
    `type` tinyint NOT NULL,
    `metadata` longtext,
    `data` longtext
)";
// TODO add foreign key constraints and indexes

if (!$mysqli->query($query)) {
    die("Failed to create table: " . "record");
}
?>