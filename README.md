[![Build Status](https://travis-ci.org/fkooman/php-lib-crypto.svg)](https://travis-ci.org/fkooman/php-lib-crypto)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/?branch=master)

# Introduction
A simple symmetric encryption and decryption library using secure hashes with 
zero configuration.

In the future an asymmetric (public key) class may be added.

# Use Cases
A number of use cases:
* safely store data in a (remote) database
* use it for authorization and access tokens in e.g. an OAuth server requiring
  no token storage database
* communicate securely between two parties where keys have already been 
  exchanged in a secure way out of band

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
and the encrypted plain text. The payload is a BASE64URL encoded JSON string:

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
appended with a `.` as separator. This entire string is needed to decrypt the 
cipher text.

## Decryption
The decryption process starts by verifying the signature by calculating the
signature over the BASE64URL encoded payload it receives (the part before the 
`.`). The generated signature is then compared in a timing attack safe way 
against the received signature. If they match the BASE64URL encoded JSON 
payload is decoded and the `i` (IV) value used to perform the decryption of 
the `c` field as mentioned in the encryption section.

## Replay Attacks
If you want to avoid replay attacks, the IV could be used as a nonce,
however this is **NOT** recommended as it would break the abstraction.

A better way is to encode a nonce in the actual plain text to be encrypted.

    ...

    $plainText = json_encode(
        array(
            'nonce' => '17c349cfdfa52ff5191fac734a84f50b',
            'uid' => 'john.doe',
            'display_name' => 'John Doe'
            'iat' => 1436776121
        )
    );

    $s->encrypt($plainText);

    ...

Now your application can keep a list of `nonces` that were used before. If you
also incorporate an `iat` (issued at) field and define an expiry the list of 
nonces you need to keep track of can be limited.

## JWT/JWS/JWE
The design is loosely based on the JWT, JWS and JWE specifications, but a lot 
simpler. The algorithms are hard coded. In the future it may be possible to 
make it compatible with JWE. If this is possible it MUST NOT lead to 
additional configuration for the user of the library.
