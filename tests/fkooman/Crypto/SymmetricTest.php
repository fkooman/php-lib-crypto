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
        $key = Key::load('eyJlIjoieENVbV9FOWotdUJsSDAyOTJ4b2MxdyIsInMiOiJCNVpkVjB5WGNVWDl6dXZ0bkUzOFpTc2xvbVowb19DaUJzWF8zcWMyUExZIn0');

        $c = new Symmetric($key);
        $cipherText = 'eyJpIjoicm14ZmhKYzVMcWRqTzhVaUV3a1ZDQSIsImMiOiIza212U2NpSU1uUEFyWlkyNXpGamlRPT0iLCJtIjoiYWVzLTEyOC1jYmMiLCJoIjoic2hhMjU2In0.oJnvVxXz8otc9zijGYFoz5P7NRGfc2_c7QhM20AnkaM';
        $this->assertSame(
            'Hello World!',
            $c->decrypt($cipherText)
        );

        $cipherData = substr(
            $cipherText,
            0,
            strpos(
                $cipherText,
                '.'
            )
        );

        $this->assertSame(
            array(
                'i' => 'rmxfhJc5LqdjO8UiEwkVCA',
                'c' => '3kmvSciIMnPArZY25zFjiQ==',
                'm' => 'aes-128-cbc',
                'h' => 'sha256',
            ),
            Json::decode(
                Base64Url::decode(
                    $cipherData
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
        $key = Key::load('eyJlIjoiTER2MXZWNnJyS3FGalB0VHdVb3NxdyIsInMiOiJMWTNVaVo1SjZvbzZYaG1ZaXRnczBBb3pTbEpoNE5sd3ZJUnZOZmFjcGFBIn0');

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
