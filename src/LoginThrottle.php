<?php

namespace VoltCMS\UserAccess;

// Shared-storage brute-force lockout keyed by identifier + client IP.
//
// The per-session attempt counter in SessionAuth is trivially bypassed: an
// attacker who never sends the session cookie gets a fresh counter on every
// request, and HTTP Basic auth has no counter at all. LoginThrottle persists
// failure counts to the filesystem (outside any single session), so lockout
// survives cookie drops and applies to both the session and Basic-auth paths.
//
// Records are small JSON files keyed by a hash of "<identifier>|<ip>". After
// $maxAttempts failures within $window seconds the key is locked until the
// window elapses since the last failure; a successful login clears the record.
class LoginThrottle
{
    private $directory;
    private $maxAttempts;
    private $window;

    public function __construct(?string $directory = null, int $maxAttempts = 10, int $window = 900)
    {
        $this->directory = $directory ?: (sys_get_temp_dir() . '/voltcms_useraccess_throttle');
        $this->maxAttempts = max(1, $maxAttempts);
        $this->window = max(1, $window);
        if (!is_dir($this->directory)) {
            @mkdir($this->directory, 0700, true);
        }
    }

    // Builds the throttle key. REMOTE_ADDR is used deliberately (not the
    // spoofable X-Forwarded-For) so the lockout cannot be sidestepped by
    // forging a header.
    public function key(string $identifier): string
    {
        $identifier = trim(strtolower($identifier));
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'cli';
        return $identifier . '|' . $ip;
    }

    private function path(string $key): string
    {
        return rtrim($this->directory, '/') . '/ua_throttle_' . hash('sha256', $key) . '.json';
    }

    private function read(string $key): array
    {
        $path = $this->path($key);
        if (!is_file($path)) {
            return ['count' => 0, 'first' => 0, 'last' => 0];
        }
        $record = json_decode((string) @file_get_contents($path), true);
        if (!is_array($record) || !isset($record['count'], $record['last'])) {
            return ['count' => 0, 'first' => 0, 'last' => 0];
        }
        // A record whose window has fully elapsed is treated as empty.
        if (time() - (int) $record['last'] >= $this->window) {
            return ['count' => 0, 'first' => 0, 'last' => 0];
        }
        return $record;
    }

    public function isLocked(string $key): bool
    {
        $record = $this->read($key);
        return (int) $record['count'] >= $this->maxAttempts;
    }

    public function registerFailure(string $key): void
    {
        $record = $this->read($key);
        $now = time();
        if ((int) $record['count'] === 0) {
            $record['first'] = $now;
        }
        $record['count'] = (int) $record['count'] + 1;
        $record['last'] = $now;
        @file_put_contents($this->path($key), json_encode($record), LOCK_EX);
    }

    public function reset(string $key): void
    {
        $path = $this->path($key);
        if (is_file($path)) {
            @unlink($path);
        }
    }
}
