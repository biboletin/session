<?php

namespace Biboletin\Session;

use InvalidArgumentException;
use SessionHandlerInterface;

/**
 * Class EncryptedSessionHandler
 *
 * This class implements the SessionHandlerInterface to provide encrypted session storage.
 * It uses OpenSSL encryption to secure session data before storing it to the filesystem.
 *
 * @package Biboletin\Session
 */
class EncryptedSessionHandler implements SessionHandlerInterface
{
    /**
     * The encryption cipher method to use (AES-256-CBC or AES-128-CBC)
     *
     * @var string
     */
    private string $encrypter;

    /**
     * The directory path where session files will be stored
     *
     * @var string
     */
    private $savePath;

    /**
     * The encryption key used for encrypting and decrypting session data
     *
     * @var string
     */
    private $key;

    /**
     * Constructor for the EncryptedSessionHandler
     *
     * Initializes the session handler with the encryption key and cipher method.
     *
     * @param string $key      The encryption key (must be exactly 32 characters long)
     * @param string $encrypter The encryption cipher method to use (default: AES-256-CBC)
     *
     * @throws InvalidArgumentException If the key length is not 32 characters or if an invalid encrypter is specified
     */
    public function __construct(string $key, string $encrypter = 'AES-256-CBC')
    {
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('The encryption key must be 32 characters long.');
        }
        if (!in_array($encrypter, ['AES-256-CBC', 'AES-128-CBC'])) {
            throw new InvalidArgumentException('Invalid encrypter specified. Use AES-256-CBC or AES-128-CBC.');
        }

        $this->encrypter = $encrypter;
        $this->key = $key;
    }

    /**
     * Close the session
     *
     * This method is called when the session is closed. In this implementation,
     * no special action is needed, so it always returns true.
     *
     * @return bool Always returns true
     */
    public function close(): bool
    {
        return  true;
    }

    /**
     * Destroy a session
     *
     * Removes the session file associated with the given session ID.
     *
     * @param string $id The session ID
     *
     * @return bool True if the session was successfully destroyed or didn't exist, false otherwise
     */
    public function destroy(string $id): bool
    {
        $file = $this->savePath . '/sess_' . $id . '.session';

        return !file_exists($file) || unlink($file);
    }

    /**
     * Garbage collection
     *
     * Removes expired session files based on the maximum lifetime.
     *
     * @param int $max_lifetime The maximum lifetime of session files in seconds
     *
     * @return int|false The number of deleted session files or false on failure
     */
    public function gc(int $max_lifetime): int|false
    {
        $files = glob($this->savePath . '/sess_*');
        foreach ($files as $file) {
            if (filemtime($file) + $max_lifetime < time()) {
                unlink($file);
            }
        }
        return true;
    }

    /**
     * Open the session
     *
     * Initializes the session storage path and creates the directory if it doesn't exist.
     *
     * @param string $path The path where session files will be stored
     * @param string $name The session name
     *
     * @return bool True if the path is writable, false otherwise
     */
    public function open(string $path, string $name): bool
    {
        $this->savePath = $path;

        if (!is_dir($path)) {
            mkdir($path, 0777, true);
        }

        return is_writable($path);
    }

    /**
     * Read session data
     *
     * Reads and decrypts the session data for the given session ID.
     *
     * @param string $id The session ID
     *
     * @return string|false The decrypted session data or an empty string if the session doesn't exist,
     *                      or false on failure
     */
    public function read(string $id): string|false
    {
        $file = "$this->savePath/sess_$id";

        if (!file_exists($file)) {
            return '';
        }

        $data = file_get_contents($file);
        return $this->decrypt($data);
    }

    /**
     * Write session data
     *
     * Encrypts and writes the session data to the storage.
     *
     * @param string $id   The session ID
     * @param string $data The session data to write
     *
     * @return bool True on success, false on failure
     */
    public function write(string $id, string $data): bool
    {
        $file = $this->savePath . "/sess_$id";
        $encrypted = $this->encrypt($data);
        return file_put_contents($file, $encrypted) !== false;
    }

    /**
     * Encrypt data
     *
     * Encrypts the given data using the configured encryption method and key.
     *
     * @param string $data The data to encrypt
     *
     * @return string The encrypted data, base64 encoded
     */
    private function encrypt(string $data): string
    {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->encrypter));
        $encrypted = openssl_encrypt($data, $this->encrypter, $this->encrypter, 0, $iv);
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt data
     *
     * Decrypts the given data using the configured encryption method and key.
     *
     * @param string $data The base64 encoded encrypted data
     *
     * @return string|false The decrypted data or false on failure
     */
    private function decrypt(string $data): string|false
    {
        $data = base64_decode($data);
        $iv_length = openssl_cipher_iv_length($this->encrypter);
        $iv = substr($data, 0, $iv_length);
        $encrypted = substr($data, $iv_length);
        return openssl_decrypt($encrypted, $this->encrypter, $this->encrypter, 0, $iv);
    }
}
