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
use fkooman\IO\IO;

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

        self::verifyKey('encrypt', $keyData['e'], self::ENCRYPT_KEY_BYTE_LENGTH);
        self::verifyKey('sign', $keyData['s'], self::SIGN_KEY_BYTE_LENGTH);

        return new self($keyData['e'], $keyData['s']);
    }

    public static function generate(IO $io = null)
    {
        if (null === $io) {
            $io = new IO();
        }
        $encryptKey = self::generateKey($io, self::ENCRYPT_KEY_BYTE_LENGTH);
        $signKey = self::generateKey($io, self::SIGN_KEY_BYTE_LENGTH);

        return new self($encryptKey, $signKey);
    }

    private static function generateKey(IO $io, $keyLength)
    {
        return Base64Url::encode(
            $io->getRandom($keyLength, true)
        );
    }

    public function getEncryptKey()
    {
        return Base64Url::decode($this->encryptKey);
    }

    public function getSignKey()
    {
        return Base64Url::decode($this->signKey);
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

        // check if the string contains only hexadecimal characters
        if (0 === preg_match('/^[A-Za-z0-9-_]*$/', $keyValue)) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be a valid base64url string', $keyType)
            );
        }

        $decodedLength = strlen(Base64Url::decode($keyValue));
        if ($keyLength !== $decodedLength) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be length %d, but has length %d', $keyType, $keyLength, $decodedLength)
            );
        }
    }
}
