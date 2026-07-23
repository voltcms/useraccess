<?php

namespace VoltCMS\UserAccess;

// Append-only audit log for administrative actions (who created / modified /
// deleted whom). Entries are written as JSON Lines (one JSON object per line)
// so the log is both human-greppable and machine-parseable, and appends are
// atomic (`FILE_APPEND | LOCK_EX`).
//
// Auditing is OFF unless a directory is configured, and every write is
// best-effort: a logging failure must never break the request being recorded.
// The log holds usernames/display names and actor IPs, so — like the entity
// store — its directory is dropped a deny-all `.htaccess` and should live
// outside the web root.
class AuditLog
{
    private $file = null;

    public function __construct(?string $directory = null, string $filename = 'audit.log')
    {
        if ($directory === null || $directory === '') {
            return; // disabled
        }
        if (!is_dir($directory)) {
            @mkdir($directory, 0750, true);
        }
        if (is_dir($directory) && is_writable($directory)) {
            Utils::protectDirectory($directory);
            $this->file = rtrim($directory, '/') . '/' . $filename;
        }
    }

    public function isEnabled(): bool
    {
        return $this->file !== null;
    }

    public function getFile(): ?string
    {
        return $this->file;
    }

    // Appends one audit entry as a JSON line. An ISO-8601 UTC `time` field is
    // added automatically when absent. No-op when disabled or unwritable.
    public function record(array $entry): void
    {
        if ($this->file === null) {
            return;
        }
        if (!array_key_exists('time', $entry)) {
            $entry = array_merge(array('time' => gmdate('c')), $entry);
        }
        $line = json_encode($entry, JSON_UNESCAPED_SLASHES);
        if ($line === false) {
            return;
        }
        @file_put_contents($this->file, $line . "\n", FILE_APPEND | LOCK_EX);
    }
}
