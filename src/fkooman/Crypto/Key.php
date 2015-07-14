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

use InvalidArgumentException;
use fkooman\Base64\Base64Url;
use fkooman\Json\Json;

class Key
{
    const ENCRYPT_KEY_BYTE_LENGTH = 16;
    const SIGN_KEY_BYTE_LENGTH = 32;

    /** @var string */
    private $encryptKey;

    /** @var string */
    private $signKey;

    private function __construct($encryptKey, $signKey)
    {
        $this->encryptKey = $encryptKey;
        $this->signKey = $signKey;
    }

    public static function load($keyData)
    {
        $jsonKeyData = Base64Url::decode($keyData);
        $keyData = Json::decode($jsonKeyData);
        if (!array_key_exists('e', $keyData) || !array_key_exists('s', $keyData)) {
            throw new InvalidArgumentException('invalid key data');
        }

        self::verifyKey('encrypt', $keyData['e'], 2 * self::ENCRYPT_KEY_BYTE_LENGTH);
        self::verifyKey('sign', $keyData['s'], 2 * self::SIGN_KEY_BYTE_LENGTH);

        return new self($keyData['e'], $keyData['s']);
    }

    public static function generate()
    {
        $encryptKey = bin2hex(openssl_random_pseudo_bytes(self::ENCRYPT_KEY_BYTE_LENGTH));
        $signKey = bin2hex(openssl_random_pseudo_bytes(self::SIGN_KEY_BYTE_LENGTH));

        return new self($encryptKey, $signKey);
    }

    public function getEncryptKey()
    {
        return hex2bin($this->encryptKey);
    }

    public function getSignKey()
    {
        return hex2bin($this->signKey);
    }

    public function __toString()
    {
        $keyData = array(
            'e' => $this->encryptKey,
            's' => $this->signKey,
        );

        return Base64Url::encode(Json::encode($keyData));
    }

    private static function verifyKey($keyType, $keyValue, $keyLength)
    {
        if (!is_string($keyValue)) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be string', $keyType)
            );
        }

        // hex length must be twice as long as byte length
        if ($keyLength !== strlen($keyValue)) {
            throw new InvalidArgumentException(
                sprintf('hex representation of %s key MUST be length %d', $keyType, $keyLength)
            );
        }

        // try to turn hex into bin
        if (false === @hex2bin($keyValue)) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be a valid hex string', $keyType)
            );
        }
    }
}
