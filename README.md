[![Build Status](https://travis-ci.org/fkooman/php-lib-crypto.svg)](https://travis-ci.org/fkooman/php-lib-crypto)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/fkooman/php-lib-crypto/?branch=master)

# Introduction
**PLEASE DO NOT YET USE**

A simple encryption/decryption library with zero configuration.

# Design
This library allows you to encrypt and decrypt data. The generated cipher text
is secured using a signature. 

Currently the `aes-128-cbc` ciper is used together with a `sha256` HMAC. For 
the encryption and signing different keys MUST be used.

## Encryption
The cipher text consists of the payload and the signature:

    (Base64Url) payload "." (Base64Url) signature

The payload contains the IV, the name of the used algorithms and the encrypted
plaint text. The payload is a Base64Url encoded JSON string:

    {
        "c": "ogjdXXPgXKAe01IMD0C8Yg==",
        "h": "sha256",
        "i": "4f419113c088fccb7c6f17a7a199f8aa",
        "m": "aes-128-cbc"
    }

`c` is the base64 encoded encrypted plain text, `h` is the using HMAC algorithm,
`i` is the IV in hex format and `m` is the used encryption cipher. The `h` and
`m` fields are NEVER used in the decryption process, but only informative.

The signature is calculated over the Base64Url encoded JSON encoded payload and
appended with a `.` as separator. A complete example:

    eyJpIjoiNGY0MTkxMTNjMDg4ZmNjYjdjNmYxN2E3YTE5OWY4YWEiLCJjIjoib2dqZFhYUGdYS0FlMDFJTUQwQzhZZz09IiwibSI6ImFlcy0xMjgtY2JjIiwiaCI6InNoYTI1NiJ9.poRFNxkom2iqiUcQ7v88AkKmK_HA_CEsRNOlvpoTXA0

This entire string is needed to decrypt the cipher text.

## Decryption
The decryption process starts by verifying the signature by calculating the
signature over the Base64Url encoded payload it receives (the part before the 
`.`). The generated signature is then (timing safe) compared against the 
received signature. If they match the Base64Url encoded JSON payload is 
decoded and the `i` (IV) value used to perform the decryption of the `c` field 
as mentioned in the encryption section.

## JWT/JWS/JWE
The design is loosly based on the JWT, JWS and JWE specifications, but a lot 
simpler. The algorithms are hard coded. In the future it may be possible to 
make it compatible with JWE. If this is possible it MUST NOT lead to 
additional configuration for the user of the library.
