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
        $this->assertEquals(
            $plainText,
            $c->decrypt($cipherText)
        );
    }
}
