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

class Utils
{
    public static function hashEquals($safe, $user)
    {
        // PHP >= 5.6.0 has "hash_equals"
        if (function_exists('hash_equals')) {
            return hash_equals($safe, $user);
        }

        return self::timingSafeEquals($safe, $user);
    }

    /**
     * A timing safe equals comparison.
     *
     * @param string $safe The internal (safe) value to be checked
     * @param string $user The user submitted (unsafe) value
     *
     * @return bool True if the two strings are identical.
     *
     * @see http://blog.ircmaxell.com/2014/11/its-all-about-time.html
     */
    public static function timingSafeEquals($safe, $user)
    {
        $safeLen = strlen($safe);
        $userLen = strlen($user);

        if ($userLen != $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($safe[$i]) ^ ord($user[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return $result === 0;
    }

    public static function verifyKey($keyType, $keyValue)
    {
        if (!is_string($keyValue)) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be string', $keyType)
            );
        }
        if (Symmetric::SECRET_MIN_LENGTH > strlen($keyValue)) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be at least length %d', $keyType, Symmetric::SECRET_MIN_LENGTH)
            );
        }
        $binKey = @hex2bin($keyValue);
        if (false === $keyValue) {
            throw new InvalidArgumentException(
                sprintf('%s key MUST be a valid hex string', $keyType)
            );
        }

        return $binKey;
    }
}
