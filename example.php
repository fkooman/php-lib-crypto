<?php

require_once 'vendor/autoload.php';

use fkooman\Crypto\Symmetric;
use fkooman\Crypto\Key;

try {
    $plainText = 'Hello World!';

    echo 'plainText : '.$plainText.PHP_EOL;

    $key = Key::generate();
    echo 'key:      : '.$key.PHP_EOL;

    $c = new Symmetric($key);

    $cipherText = $c->encrypt($plainText);
    echo 'cipherText: '.$cipherText.PHP_EOL;

    $plainText = $c->decrypt($cipherText);
    echo 'plainText : '.$plainText.PHP_EOL;
} catch (Exception $e) {
    echo $e->getMessage().PHP_EOL;
    exit(1);
}
