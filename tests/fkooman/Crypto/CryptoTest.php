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
use PHPUnit_Framework_TestCase;

class CryptoTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $encryptSecret = bin2hex(openssl_random_pseudo_bytes(16));
        $signSecret = bin2hex(openssl_random_pseudo_bytes(16));
        $plainText = 'Hello World!';

        $c = new Crypto($encryptSecret, $signSecret);
        $cipherText = $c->encrypt($plainText);
        $this->assertSame(
            $plainText,
            $c->decrypt($cipherText)
        );
    }

    public function testDecrypt()
    {
        $c = new Crypto('bf76d65e841dcb5bb9e45a6e9027393d', '57d8eb862864f427d02f7364afe52732');
        $cipherText = 'eyJpIjoiNGY2YzM2MTE0YjBkYTM2Nzg5MzYxNzA3YzQ2NDMyMDEiLCJjIjoiRUw0dG80bkVQMDRBYkdtV1dGR1wvOWc9PSIsIm0iOiJhZXMtMTI4LWNiYyIsImgiOiJzaGEyNTYifQ.b3mCkMDCoclvSVN5dIyHc9htW6AIsD4o9z35nYamrts';
        $this->assertSame(
            'Hello World',
            $c->decrypt($cipherText)
        );

        $this->assertSame(
            array(
                'i' => '4f6c36114b0da36789361707c4643201',
                'c' => 'EL4to4nEP04AbGmWWFG/9g==',
                'm' => 'aes-128-cbc',
                'h' => 'sha256',
            ),
            json_decode(
                Base64Url::decode(
                    explode('.', $cipherText)[0]
                ),
                true
            )
        );
    }

    /**
     * @expectedException RuntimeException
     * @expectedMessageException invalid signture
     */
    public function testInvalidSignature()
    {
        $c = new Crypto('bf76d65e841dcb5bb9e45a6e9027393d', '57d8eb862864f427d02f7364afe52732');
        $cipherText = 'eyJpIjoiMjhkZTAyNzYyMmEzMzUzMjFhYTI1OGFlZDMxMzMxMDQiLCJjIjoidmZ3Y2ZHTituSEV1c0Z6UWpuZ2JyUT09IiwibSI6ImFlcy0xMjgtY2JjIiwiaCI6InNoYTI1NiJ9.b3mCkMDCoclvSVN5dIyHc9htW6AIsD4o9z35nYamrts';
        $c->decrypt($cipherText);
    }
}
