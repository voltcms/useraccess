<?php

namespace VoltCMS\UserAccess;

// Process-wide advisory write mutex for the flat-file store.
//
// FileDB has no locking of its own, so concurrent requests that mutate the
// same documents can interleave and corrupt data — the user-delete path is the
// worst offender (delete the user, then loop-update every group is a multi-step,
// cross-provider sequence). Wrapping every mutation in Lock::exclusive()
// serializes writers via flock(LOCK_EX) on a single lock file.
//
// The lock is REENTRANT within a process: a single shared file handle plus a
// depth counter means nested acquisitions (e.g. UserProvider::delete calling
// GroupProvider::update) do not deadlock against themselves and the outermost
// call is the one that finally releases. Reads are intentionally left unlocked;
// the worst case is a reader observing pre-write state, never corruption.
//
// This is the pragmatic fix for a flat-file store; a high-concurrency
// deployment should move to a transactional backend (see CLAUDE.md).
class Lock
{
    private static $handle = null;
    private static int $depth = 0;

    private static function handle()
    {
        if (self::$handle === null) {
            // One lock file per library installation (the src path is stable
            // per install and unique across installs, so separate deployments
            // sharing a host do not contend on the same mutex).
            $path = sys_get_temp_dir() . '/voltcms_useraccess_' . md5(__DIR__) . '.lock';
            self::$handle = @fopen($path, 'c');
        }
        return self::$handle;
    }

    // Runs $callback while holding the exclusive write lock and returns its
    // result. If the lock cannot be obtained (e.g. the temp dir is not
    // writable) the callback still runs — locking is best-effort and must
    // never prevent the application from functioning.
    public static function exclusive(callable $callback)
    {
        $handle = self::handle();
        $acquired = false;
        if ($handle !== false && $handle !== null) {
            if (self::$depth === 0) {
                $acquired = @flock($handle, LOCK_EX);
            }
            self::$depth++;
        }
        try {
            return $callback();
        } finally {
            if ($handle !== false && $handle !== null) {
                self::$depth--;
                if (self::$depth === 0 && $acquired) {
                    @flock($handle, LOCK_UN);
                }
            }
        }
    }
}
