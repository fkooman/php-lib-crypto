<?php

require_once 'vendor/autoload.php';
use fkooman\Crypto\Crypto;

try {
    $c = new Crypto('bf76d65e841dcb5bb9e45a6e9027393d', '57d8eb862864f427d02f7364afe52732');

    $plainText = 'Hello World';
    echo $plainText.PHP_EOL;

    $cipherText = $c->encrypt($plainText);
    echo $cipherText.PHP_EOL;

    $plainText = $c->decrypt($cipherText);
    echo $plainText.PHP_EOL;
} catch (Exception $e) {
    echo $e->getMessage().PHP_EOL;
    exit(1);
}
