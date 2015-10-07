# Changes

## 2.0.0 (2015-10-07)
- use `fkooman/io` for random number generation
- remove `bin2hex` and `pack` usage and use `Base64Url` to encode the 
  keys and IV
- **NOTE**: data encrypted/signed by version 1 of this library cannot
  be decrypted/verified by version 2

## 1.0.1
- restore compatibility with PHP 5.3

## 1.0.0
- initial release
