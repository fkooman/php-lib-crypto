<?php

namespace fkooman\Crypto;

use fkooman\Base64\Base64Url;
use fkooman\Json\Json;
use InvalidArgumentException;
use RuntimeException;

class Crypto
{
    /** @var string */
    private $encryptionKey;

    /** @var string */
    private $signingKey;

    const CIPHER_METHOD = 'aes-128-cbc';
    const HASH_METHOD = 'sha256';
    const SECRET_MIN_LENGTH = '32';

    public function __construct($encryptionKey, $signingKey)
    {
        if (!is_string($encryptionKey)) {
            throw new InvalidArgumentException('encryption key MUST be string');
        }
        if (!is_string($signingKey)) {
            throw new InvalidArgumentException('signing key MUST be string');
        }
        if (self::SECRET_MIN_LENGTH > strlen($encryptionKey)) {
            throw new InvalidArgumentException(sprintf('encryption key MUST be at least length %d', self::SECRET_MIN_LENGTH));
        }
        if (self::SECRET_MIN_LENGTH > strlen($signingKey)) {
            throw new InvalidArgumentException(sprintf('signing key MUST be at least length %d', self::SECRET_MIN_LENGTH));
        }
        if ($encryptionKey === $signingKey) {
            throw new InvalidArgumentException('encryption and signing keys MUST NOT be the same');
        }

        $encryptionKey = @hex2bin($encryptionKey);
        if (false === $encryptionKey) {
            throw new InvalidArgumentException('encryption key MUST be a valid hex string');
        }

        $signingKey = hex2bin($signingKey);
        if (false === $signingKey) {
            throw new InvalidArgumentException('signing key is not a valid hex string');
        }

        $this->encryptionKey = $encryptionKey;
        $this->signingKey = $signingKey;
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
