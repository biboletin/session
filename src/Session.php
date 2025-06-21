<?php

namespace Biboletin\Session;

use InvalidArgumentException;
use Random\RandomException;
use RuntimeException;
use SessionHandlerInterface;

/**
 * Session management class.
 *
 * This class provides a comprehensive wrapper around PHP's native session functionality,
 * offering methods to start, destroy, and manipulate sessions, as well as to configure
 * session parameters like lifetime, path, domain, etc.
 */
class Session
{
    /**
     * Flag indicating whether the session has been started.
     */
    protected bool $started = false;

    /**
     * The name of the session, used in cookies and URLs.
     */
    protected string $name = 'PHPSESSID';

    /**
     * Session lifetime in seconds. 0 means "until the browser is closed".
     */
    protected int $lifetime = 0;

    /**
     * The path on the server in which the cookie will be available.
     */
    protected string $path = '/';

    /**
     * The domain that the cookie is available to.
     */
    protected string $domain = '';

    /**
     * Whether the cookie should only be transmitted over a secure HTTPS connection.
     */
    protected bool $secure = false;

    /**
     * Whether the cookie should be accessible only through the HTTP protocol.
     * When set to true, the cookie won't be accessible by JavaScript.
     */
    protected bool $httpOnly = true;

    /**
     * The directory where session files are stored.
     */
    protected string $savePath = '';

    /**
     * The SameSite attribute for the session cookie.
     * Possible values: 'Lax', 'Strict', 'None'.
     */
    protected string $sameSite = 'Lax';

    /**
     * The session ID.
     */
    protected string $id = '';

    /**
     * The session data array.
     */
    protected array $data = [];

    /**
     * The key used for flash messages in the session data.
     */
    protected string $flashKey = '_flash';

    /**
     * The session handler instance used for storing and retrieving session data.
     */
    protected SessionHandlerInterface $handler;

    /**
     * Initializes a new Session instance.
     *
     * Reads session configuration from PHP ini settings and sets default values
     * for session parameters.
     *
     * @throws RandomException
     */
    public function __construct()
    {
        $this->name = ini_get('session.name') ?: 'PHPSESSID';
        $this->lifetime = (int)ini_get('session.cookie_lifetime') ?: 0;
        $this->path = ini_get('session.cookie_path') ?: '/';
        $this->domain = ini_get('session.cookie_domain') ?: '';
        $this->secure = ini_get('session.cookie_secure') === '1';
        $this->httpOnly = ini_get('session.cookie_httponly') === '1';
        $this->sameSite = ini_get('session.cookie_samesite') ?: 'Lax';
        $this->savePath = ini_get('session.save_path') ?: sys_get_temp_dir();
        
        $this->handler = new EncryptedSessionHandler();
    }

    /**
     * Starts the session.
     *
     * Configures session parameters and starts a new session or resumes an existing one.
     * If the session is already started, this method does nothing.
     */
    public function start(): void
    {
        if ($this->started) {
            return;
        }

        if ($this->savePath) {
            session_save_path($this->savePath);
        }

        if ($this->id) {
            session_id($this->id);
        }

        session_name($this->name);
        session_set_cookie_params([
            'lifetime' => $this->getLifetime(),
            'path' => $this->getPath(),
            'domain' => $this->getDomain(),
            'secure' => $this->getSecure(),
            'httponly' => $this->getHttpOnly(),
            'samesite' => $this->getSameSite(),
        ]);

        session_set_save_handler($this->handler, true);
        $this->setId(session_id());
        session_start();

        $this->setData($_SESSION);
        $this->started = true;
    }

    /**
     * Destroys the session.
     *
     * Unsets all session data and destroys the session. If the session is not started,
     * this method does nothing.
     */
    public function destroy(): void
    {
        if (!$this->started) {
            return;
        }

        session_unset();
        session_destroy();

        unset($_SESSION);
        $_SESSION = [];

        $this->started = false;
        $this->id = '';
        $this->savePath = '';
        $this->data = [];
    }

    /**
     * Checks if the session is started.
     *
     * @return bool True if the session is started, false otherwise.
     */
    public function isStarted(): bool
    {
        return $this->started;
    }

    /**
     * Gets the session ID.
     *
     * @return string The current session ID.
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * Generates a new session ID.
     *
     * @param string $prefix Optional prefix for the session ID.
     *
     * @return string|false The new session ID or false on failure.
     */
    public function generateId(string $prefix = ''): string|false
    {
        return session_create_id($prefix);
    }

    /**
     * Sets the session ID.
     *
     * @param string $prefix Optional prefix for the session ID.
     *
     * @throws RuntimeException If the session is already started.
     */
    public function setId(string $prefix = ''): void
    {
        if ($this->started) {
            throw new RuntimeException('Cannot set session ID after the session has started.');
        }
        session_id(session_create_id($prefix));
        $this->id = session_id();
    }

    /**
     * Sets the session save path.
     *
     * @param string $path The directory path where session files will be stored.
     *
     * @throws InvalidArgumentException If the path cannot be created or is not writable.
     * @throws RuntimeException If the session is already started.
     */
    public function setSavePath(string $path): void
    {
        if (!is_dir($path) && !mkdir($path, 0777, true) && !is_dir($path)) {
            throw new InvalidArgumentException("Unable to create the session save path '" . $path . "'.");
        }

        if (!is_writable($path)) {
            throw new InvalidArgumentException("The save path '" . $path . "' is not writable.");
        }

        if ($this->started) {
            throw new RuntimeException('Cannot set save path after the session has started.');
        }

        $this->savePath = $path;
        session_save_path($path);
    }

    /**
     * Gets the session save path.
     *
     * @return string The directory path where session files are stored.
     */
    public function getSavePath(): string
    {
        return $this->savePath;
    }

    /**
     * Sets the session name.
     *
     * @param string $name The name of the session.
     *
     * @throws RuntimeException If the session is already started.
     */
    public function setSessionName(string $name): void
    {
        if ($this->started) {
            throw new RuntimeException('Cannot change session name after it has started.');
        }
        $this->name = $name;
    }

    /**
     * Gets the session name.
     *
     * @return string The name of the session.
     */
    public function getSessionName(): string
    {
        return $this->name;
    }

    /**
     * Gets the session name (alias for getSessionName).
     *
     * @return string The name of the session.
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Gets the session lifetime.
     *
     * @return int The session lifetime in seconds.
     */
    public function getLifetime(): int
    {
        return $this->lifetime;
    }

    /**
     * Gets the session cookie path.
     *
     * @return string The path on the server in which the cookie will be available.
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * Gets the session cookie domain.
     *
     * @return string The domain that the cookie is available to.
     */
    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * Checks if the session cookie is secure.
     *
     * @return bool True if the cookie should only be transmitted over a secure HTTPS connection.
     */
    public function isSecure(): bool
    {
        return $this->secure;
    }

    /**
     * Checks if the session cookie is HTTP only.
     *
     * @return bool True if the cookie should be accessible only through the HTTP protocol.
     */
    public function isHttpOnly(): bool
    {
        return $this->httpOnly;
    }

    /**
     * Sets the session lifetime.
     *
     * @param int $lifetime The session lifetime in seconds.
     */
    public function setLifeTime(int $lifetime): void
    {
        $this->lifetime = $lifetime;
    }

    /**
     * Sets the session cookie path.
     *
     * @param string $path The path on the server in which the cookie will be available.
     */
    public function setPath(string $path): void
    {
        $this->path = $path;
    }

    /**
     * Sets the session cookie domain.
     *
     * @param string $domain The domain that the cookie is available to.
     */
    public function setDomain(string $domain): void
    {
        $this->domain = $domain;
    }

    /**
     * Sets the session cookie secure flag.
     *
     * @param bool $secure Whether the cookie should only be transmitted over a secure HTTPS connection.
     */
    public function setSecure(bool $secure): void
    {
        $this->secure = $secure;
    }

    /**
     * Sets the session cookie HTTP only flag.
     *
     * @param bool $httpOnly Whether the cookie should be accessible only through the HTTP protocol.
     */
    public function setHttpOnly(bool $httpOnly): void
    {
        $this->httpOnly = $httpOnly;
    }

    /**
     * Sets the SameSite attribute for the session cookie.
     *
     * @param string $sameSite The SameSite attribute value ('Lax', 'Strict', or 'None').
     *
     * @throws InvalidArgumentException If the provided value is not one of the allowed values.
     */
    public function setSameSite(string $sameSite): void
    {
        $validValues = ['Lax', 'Strict', 'None'];
        if (!in_array($sameSite, $validValues, true)) {
            throw new InvalidArgumentException(
                'Invalid SameSite value. Allowed values are: ' . implode(', ', $validValues)
            );
        }

        $this->sameSite = $sameSite;
    }

    /**
     * Gets the SameSite attribute for the session cookie.
     *
     * @return string The SameSite attribute value.
     */
    public function getSameSite(): string
    {
        return $this->sameSite;
    }

    /**
     * Gets all session data.
     *
     * @return array The session data array.
     */
    public function getData(): array
    {
        return $this->data;
    }

    /**
     * Sets multiple session data values at once.
     *
     * @param array $data An associative array of session data to set.
     */
    public function setData(array $data): void
    {
        $this->data = array_merge($this->data, $data);
        $_SESSION = array_merge($_SESSION, $data);
    }

    /**
     * Gets a session data value by key.
     *
     * @param string $key     The key to retrieve.
     * @param mixed  $default The default value to return if the key doesn't exist.
     *
     * @return mixed The value associated with the key or the default value.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * Checks if a session data key exists.
     *
     * @param string $key The key to check.
     *
     * @return bool True if the key exists, false otherwise.
     */
    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    /**
     * Sets a session data value.
     *
     * @param string $key   The key to set.
     * @param mixed  $value The value to set.
     */
    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
        $_SESSION[$key] = $value;
    }

    /**
     * Removes a session data value.
     *
     * @param string $key The key to remove.
     */
    public function remove(string $key): void
    {
        unset($this->data[$key], $_SESSION[$key]);
    }

    /**
     * Clears all session data.
     */
    public function clear(): void
    {
        $this->data = [];
        $_SESSION = [];
    }

    /**
     * Regenerates the session ID.
     *
     * @param bool $deleteOldSession Whether to delete the old session data or not.
     */
    public function regenerateId(bool $deleteOldSession = false): void
    {
        if (!$this->started) {
            return;
        }

        session_regenerate_id($deleteOldSession);
        $this->id = session_id();
    }

    /**
     * Gets the flash messages key.
     *
     * @return string The key used for flash messages in the session data.
     */
    public function getFlashKey(): string
    {
        return $this->flashKey;
    }

    /**
     * Sets the flash messages key.
     *
     * @param string $key The key to use for flash messages in the session data.
     */
    public function setFlashKey(string $key): void
    {
        $this->flashKey = $key;
        $this->data[$this->flashKey] ??= [];
        $_SESSION[$this->flashKey] ??= [];
    }

    /**
     * Sets or retrieves a flash message.
     *
     * Flash messages are temporary data that are removed after being retrieved once.
     * If a value is provided, it sets the flash message. If no value is provided,
     * it retrieves and removes the flash message.
     *
     * @param string $key   The flash message key.
     * @param mixed  $value The flash message value to set (optional).
     *
     * @return mixed The flash message value if retrieving, or null if not found.
     */
    public function flash(string $key, mixed $value = null): mixed
    {
        if ($value !== null) {
            $this->data[$this->flashKey][$key] = $value;
            $_SESSION[$this->flashKey][$key] = $value;
        }

        if (isset($this->data[$this->flashKey][$key])) {
            $val = $this->data[$this->flashKey][$key];
            unset($this->data[$this->flashKey][$key], $_SESSION[$this->flashKey][$key]);
            return $val;
        }

        return null;
    }

    /**
     * Private method to get the secure flag for internal use.
     *
     * @return bool Whether the cookie should only be transmitted over a secure HTTPS connection.
     */
    private function getSecure(): bool
    {
        return $this->secure;
    }

    /**
     * Private method to get the HTTP only flag for internal use.
     *
     * @return bool Whether the cookie should be accessible only through the HTTP protocol.
     */
    private function getHttpOnly(): bool
    {
        return $this->httpOnly;
    }

    /**
     * Purges all session files from the session save path.
     *
     * This method deletes all session files in the current session save path directory.
     * Use with caution as it will remove all active sessions for all users.
     */
    public function purge(): void
    {
        $sessionFiles = glob(session_save_path() . '/sess_*');
        foreach ($sessionFiles as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
    }
}
