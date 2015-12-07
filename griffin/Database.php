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

$query = "CREATE TABLE IF NOT EXISTS `user` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `email` varchar(255) NOT NULL,
    `pubkey` longtext,
    `valid` bool
)";
// TODO add foreign key constraints and indexes

if (!$mysqli->query($query)) {
    die("Failed to create table: " . "user");
}

$query = "CREATE TABLE IF NOT EXISTS `secret` (
    `id` integer NOT NULL,
    `key_id` integer NOT NULL,
    `schema` tinyint NOT NULL,
    `updated` datetime NOT NULL,
    `uid` integer NOT NULL,
    `gid` integer,
    `data` longtext,
    PRIMARY KEY (`id`, `uid`)
)";
// TODO add foreign key constraints and indexes

if (!$mysqli->query($query)) {
    die("Failed to create table: " . "secret");
}

$query = "CREATE TABLE IF NOT EXISTS `sync` (
    `id` integer AUTO_INCREMENT NOT NULL PRIMARY KEY,
    `expires` datetime NOT NULL,
    `uid` integer NOT NULL,
    `data` longtext
)";
// TODO add foreign key constraints and indexes

if (!$mysqli->query($query)) {
    die("Failed to create table: " . "secret");
}
?>