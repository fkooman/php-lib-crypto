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
use PHPUnit_Framework_TestCase;

class SymmetricTest extends PHPUnit_Framework_TestCase
{
    public function testEncrypt()
    {
        $key = Key::generate();
        $plainText = 'Hello World!';

        $c = new Symmetric($key);
        $cipherText = $c->encrypt($plainText);
        $this->assertSame(
            $plainText,
            $c->decrypt($cipherText)
        );
    }

    public function testDecrypt()
    {
        $key = Key::load('eyJlIjoiZmRhMmZjOGQwMWMwZjg0NDFhODNhMzc1ODAzMWExOTkiLCJzIjoiNTNjNWU2MmRjZjZkYjM4YzNhYTgwZmUyMzVmZjY5MTI5NTdhY2YyZjI1M2ZiNTFlMjQ0NjBmZTQ4NzdmMWQ2YiJ9');

        $c = new Symmetric($key);
        $cipherText = 'eyJpIjoiOGQ4MDdjZTg1OGI0MmVlYmMyYjcyMDc2MmZjNmY1N2YiLCJjIjoiTXNjS0l5NzlINDZYazJoNDRxcG9LUT09IiwibSI6ImFlcy0xMjgtY2JjIiwiaCI6InNoYTI1NiJ9.2oRxIovyTxvExPOgTR2cYxJsUacmm-1wyIO7Izg9gp8.jM0F4_3IJe4hVrj0ApJj6nO0Cou_xUkMBSxcK_3ENqA.3W4GohB-BlGIccWgeW2cQ8FZTlwiY2G0uzMBpXapPZE';
        $this->assertSame(
            'Hello World!',
            $c->decrypt($cipherText)
        );

        $this->assertSame(
            array(
                'i' => '8d807ce858b42eebc2b720762fc6f57f',
                'c' => 'MscKIy79H46Xk2h44qpoKQ==',
                'm' => 'aes-128-cbc',
                'h' => 'sha256',
            ),
            Json::decode(
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
        $key = Key::load('eyJlIjoiZmRhMmZjOGQwMWMwZjg0NDFhODNhMzc1ODAzMWExOTkiLCJzIjoiNTNjNWU2MmRjZjZkYjM4YzNhYTgwZmUyMzVmZjY5MTI5NTdhY2YyZjI1M2ZiNTFlMjQ0NjBmZTQ4NzdmMWQ2YiJ9');

        $c = new Symmetric($key);
        $cipherText = 'eyJpIjoiMjhkZTAyNzYyMmEzMzUzMjFhYTI1OGFlZDMxMzMxMDQiLCJjIjoidmZ3Y2ZHTituSEV1c0Z6UWpuZ2JyUT09IiwibSI6ImFlcy0xMjgtY2JjIiwiaCI6InNoYTI1NiJ9.b3mCkMDCoclvSVN5dIyHc9htW6AIsD4o9z35nYamrts';
        $c->decrypt($cipherText);
    }

    public function testUtf8()
    {
        $str = 'Россия';
        $this->assertSame(12, strlen($str));
        $key = Key::generate();
        $c = new Symmetric($key);
        $cipherText = $c->encrypt($str);
        $this->assertSame($str, $c->decrypt($cipherText));
    }
}
