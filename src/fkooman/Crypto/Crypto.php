<?php

namespace fkooman\Crypto;

use fkooman\Base64\Base64Url;
use InvalidArgumentException;
use RuntimeException;

class Crypto
{
    /** @var string */
    private $encryptSecret;

    /** @var string */
    private $signSecret;

    const CIPHER_METHOD = 'aes-128-cbc';
    const HASH_METHOD = 'sha256';
    const SECRET_MIN_LENGTH = '32';

    public function __construct($encryptSecret, $signSecret)
    {
        if (!is_string($encryptSecret)) {
            throw new InvalidArgumentException('encryption secret MUST be string');
        }
        if (!is_string($signSecret)) {
            throw new InvalidArgumentException('sign secret MUST be string');
        }
        if (self::SECRET_MIN_LENGTH > strlen($encryptSecret)) {
            throw new InvalidArgumentException(sprintf('encryption secret MUST be at least length %d', self::SECRET_MIN_LENGTH));
        }
        if (self::SECRET_MIN_LENGTH > strlen($signSecret)) {
            throw new InvalidArgumentException(sprintf('sign secret MUST be at least length %d', self::SECRET_MIN_LENGTH));
        }
        if ($encryptSecret === $signSecret) {
            throw new InvalidArgumentException('encryption and sign secret MUST NOT be the same');
        }

        $this->encryptSecret = $encryptSecret;
        $this->signSecret = $signSecret;
    }

    public function encrypt($plainText)
    {
        if (!is_string($plainText)) {
            throw new InvalidArgumentException('must be string');
        }

        // generate an initialization vector
        $ivData = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length(self::CIPHER_METHOD)
        );

        // encrypt the data
        $cipherText = openssl_encrypt(
            $plainText,
            self::CIPHER_METHOD,
            $this->encryptSecret,
            0,
            $ivData
        );

        // create a container for initialization vector and cipher text
        $dataContainer = array(
            'i' => bin2hex($ivData),
            'c' => $cipherText,
            'm' => self::CIPHER_METHOD, // only informative
            'h' => self::HASH_METHOD,   // only informative
        );

        $encodedDataContainer = Base64Url::encode(json_encode($dataContainer));

        // hash
        $signatureData = hash_hmac(
            self::HASH_METHOD,
            $encodedDataContainer,
            $this->signSecret,
            true
        );
        $encodedSignatureData = Base64Url::encode($signatureData);

        return sprintf('%s.%s', $encodedDataContainer, $encodedSignatureData);
    }

    public function decrypt($cipherText)
    {
        if (!is_string($cipherText)) {
            throw new InvalidArgumentException('must be string');
        }

        if (false === strpos($cipherText, '.')) {
            throw new InvalidArgumentException('invalid ciphertext');
        }

        list($encodedDataContainer, $encodedSignatureData) = explode('.', $cipherText);

        // verify the hash
        $signatureData = hash_hmac(
            self::HASH_METHOD,
            $encodedDataContainer,
            $this->signSecret,
            true
        );
        $encodedSignatureDataGenerated = Base64Url::encode($signatureData);

        // PHP >= 5.6.0 has "hash_equals"
        if (function_exists('hash_equals')) {
            if (!hash_equals($encodedSignatureDataGenerated, $encodedSignatureData)) {
                throw new RuntimeException('invalid signture');
            }
        } else {
            if (!$this->timingSafeEquals($encodedSignatureDataGenerated, $encodedSignatureData)) {
                throw new RuntimeException('invalid signture');
            }
        }

        $dataContainer = json_decode(Base64Url::decode($encodedDataContainer), true);

        // decrypt
        $plainText = openssl_decrypt(
            $dataContainer['c'],
            self::CIPHER_METHOD,
            $this->encryptSecret,
            0,
            hex2bin($dataContainer['i'])
        );

        if (false === $plainText) {
            throw new RuntimeException('unable to decrypt cipher text');
        }

        return $plainText;
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
    private function timingSafeEquals($safe, $user)
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
}
