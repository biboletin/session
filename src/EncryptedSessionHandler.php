<?php

namespace Biboletin\Session;

use Biboletin\Crypto\Crypto;
use Biboletin\Exceptions\Custom\Crypto\DecryptException;
use Biboletin\Exceptions\Custom\Crypto\EncryptException;
use InvalidArgumentException;
use Random\RandomException;
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
    private Crypto $crypto;
    /**
     * The directory path where session files will be stored
     *
     * @var string
     */
    private string $savePath;

    /**
     * The encryption method used for session data
     * 
     * @throws RandomException
     */
    public function __construct()
    {
        // Generate a random secret key for encryption
        // 32 bytes = 256 bits
        $secret = hex2bin(bin2hex(random_bytes(32)));
        $this->crypto = new Crypto($secret);
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
        return true;
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
    public function encrypt(string $data): string
    {
        try {
            return $this->crypto->encrypt($data);
        } catch (RandomException|EncryptException $exception) {
            return $exception->getMessage();
        }
    }

    /**
     * Decrypt data
     *
     * Decrypts the given data using the configured encryption method and key.
     *
     * @param string $data The base64 encoded encrypted data
     *
     * @return string|null The decrypted data or false on failure
     */
    public function decrypt(string $data): ?string
    {
        try {
            return $this->crypto->decrypt($data) ?? null;
        } catch (InvalidArgumentException $exception) {
            return $exception->getMessage();
        }        
    }
}
