<?php

/**
 * Copyright 2015 François Kooman <fkooman@tuxed.net>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace fkooman\Crypto;

use fkooman\Base64\Base64Url;
use fkooman\Json\Json;
use InvalidArgumentException;
use RuntimeException;

class Symmetric
{
    /** @see https://secure.php.net/manual/en/function.openssl-get-cipher-methods.php */
    const CIPHER_METHOD = 'aes-128-cbc';

    /* @see https://secure.php.net/hash_algos */
    const HASH_METHOD = 'sha256';

    const SECRET_MIN_LENGTH = '32';

    /** @var string */
    private $encryptionKey;

    /** @var string */
    private $signingKey;

    public function __construct($encryptionKey, $signingKey)
    {
        $this->encryptionKey = Utils::verifyKey('encryption', $encryptionKey);
        $this->signingKey = Utils::verifyKey('signing', $signingKey);

        if ($this->encryptionKey === $this->signingKey) {
            throw new InvalidArgumentException('encryption and signing keys MUST NOT be the same');
        }
    }

    /**
     * Encrypt the provided string.
     *
     * @param string $plainText the plain text to encrypt
     *
     * @return the encrypted plain text
     */
    public function encrypt($plainText)
    {
        if (!is_string($plainText)) {
            throw new InvalidArgumentException('must be string');
        }

        // generate an initialization vector
        $iv = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length(self::CIPHER_METHOD)
        );
        // encrypt the data
        $cipherText = openssl_encrypt(
            $plainText,
            self::CIPHER_METHOD,
            $this->encryptionKey,
            0,
            $iv
        );

        // create a container for initialization vector and cipher text
        $dataContainer = array(
            'i' => bin2hex($iv),
            'c' => $cipherText,
            'm' => self::CIPHER_METHOD, // only informative
            'h' => self::HASH_METHOD,   // only informative
        );

        $encodedDataContainer = Base64Url::encode(Json::encode($dataContainer));

        $signatureData = $this->calculateHmac($encodedDataContainer);
        $encodedSignatureData = Base64Url::encode($signatureData);

        return sprintf('%s.%s', $encodedDataContainer, $encodedSignatureData);
    }

    /**
     * Decrypt the provided string.
     *
     * @param string $cipherText the cipher text to decrypt
     *
     * @return the decrypted ciphertext
     */
    public function decrypt($cipherText)
    {
        if (!is_string($cipherText)) {
            throw new InvalidArgumentException('must be string');
        }

        if (false === strpos($cipherText, '.')) {
            throw new InvalidArgumentException('invalid ciphertext');
        }

        list($encodedDataContainer, $encodedSignatureData) = explode('.', $cipherText);

        $signatureData = $this->calculateHmac($encodedDataContainer);
        $encodedSignatureDataGenerated = Base64Url::encode($signatureData);

        if (!Utils::hashEquals($encodedSignatureDataGenerated, $encodedSignatureData)) {
            throw new RuntimeException('invalid signture');
        }

        $dataContainer = Json::decode(Base64Url::decode($encodedDataContainer));

        // decrypt
        $plainText = openssl_decrypt(
            $dataContainer['c'],
            self::CIPHER_METHOD,
            $this->encryptionKey,
            0,
            hex2bin($dataContainer['i'])
        );

        if (false === $plainText) {
            throw new RuntimeException('unable to decrypt cipher text');
        }

        return $plainText;
    }

    private function calculateHmac($data)
    {
        return hash_hmac(
            self::HASH_METHOD,
            $data,
            $this->signingKey,
            true
        );
    }
}
