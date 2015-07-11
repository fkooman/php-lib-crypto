[![Build Status](https://travis-ci.org/fkooman/php-lib-crypto.svg)](https://travis-ci.org/fkooman/php-lib-crypto)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/?branch=master)

# Introduction
A simple symmetric encryption and decryption library using secure hashes with 
zero configuration.

# API
The API is very simple. The constructor takes two arguments. The encryption
and signing key. The keys need to be 128 bit or 16 bytes. 

    public function __construct($encryptionKey, $signingKey);
    public function encrypt($plainText);
    public function decrypt($cipherText);

The encryption and signing key can be generated using 
`openssl_random_pseudo_bytes()`. 

    echo bin2hex(
        openssl_random_pseudo_bytes(
            16
        )
    );

# Usage
For example consider the following program:

    use fkooman\Crypto\Symmetric;

    $encryptKey = bin2hex(openssl_random_pseudo_bytes(16));
    $signingKey = bin2hex(openssl_random_pseudo_bytes(16));

    $s = new Symmetric($encryptKey, $signingKey);
    $cipherText = $s->encrypt('Hello World!');

    echo 'cipherText: ' . $cipherText . PHP_EOL;

    $plainText = $s->decrypt($cipherText);

    echo 'plainText: ' . $plainText . PHP_EOL;

The output would look like this:

    cipherText: eyJpIjoiNDFmOTFiY2NkOTM4ZGU2NTA2Mjc1M2UxZDM3OTEwMDYiLCJjIjoibGpMTmk4aVRcL2hxWDNrNlJcL0NOOVF3PT0iLCJtIjoiYWVzLTEyOC1jYmMiLCJoIjoic2hhMjU2In0.1H38DC0XtlcWsQmhosJSdAj0mNIHQgz7zZu9vd4fSWc
    plainText: Hello World!

See design for more information on the contents of the cipher text.

# Design
This library allows you to encrypt and decrypt data. The generated cipher text
is secured using a signature. 

Currently the `aes-128-cbc` cipher is used together with a `sha256` HMAC. For 
the encryption and signing different keys MUST be used.

## Encryption
The cipher text consists of the payload and the signature:

    BASE64URL(payload) "." BASE64URL(signature)

The payload contains the initialization vector, the name of the used algorithms 
and the encrypted plaint text. The payload is a BASE64URL encoded JSON string:

    {
        "c": "ogjdXXPgXKAe01IMD0C8Yg==",
        "h": "sha256",
        "i": "4f419113c088fccb7c6f17a7a199f8aa",
        "m": "aes-128-cbc"
    }

`c` is the BASE64 encoded encrypted plain text, `h` is the used HMAC algorithm,
`i` is the IV in hex format and `m` is the used encryption cipher. The `h` and
`m` fields are NEVER used in the decryption process, but only informative.

The signature is calculated over the BASE64URL encoded JSON encoded payload and
appended with a `.` as separator. A complete example:

    eyJpIjoiNGY0MTkxMTNjMDg4ZmNjYjdjNmYxN2E3YTE5OWY4YWEiLCJjIjoib2dqZFhYUGdYS0FlMDFJTUQwQzhZZz09IiwibSI6ImFlcy0xMjgtY2JjIiwiaCI6InNoYTI1NiJ9.poRFNxkom2iqiUcQ7v88AkKmK_HA_CEsRNOlvpoTXA0

This entire string is needed to decrypt the cipher text.

## Decryption
The decryption process starts by verifying the signature by calculating the
signature over the BASE64URL encoded payload it receives (the part before the 
`.`). The generated signature is then compared in a constant time against the 
received signature. If they match the BASE64URL encoded JSON payload is 
decoded and the `i` (IV) value used to perform the decryption of the `c` field 
as mentioned in the encryption section.

## JWT/JWS/JWE
The design is loosely based on the JWT, JWS and JWE specifications, but a lot 
simpler. The algorithms are hard coded. In the future it may be possible to 
make it compatible with JWE. If this is possible it MUST NOT lead to 
additional configuration for the user of the library.
