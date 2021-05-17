<?php

namespace PragmaPHP\UserAccess;

class Sanitizer {

    public static function sanitizeString(string $value): string {
        $value = trim($value);
        $value = strtolower($value);
        $value = preg_replace('/\s+/', '-', $value);
        $value = preg_replace('/[^a-z0-9_\-]+/', '', $value);
        return $value;
    }

    public static function sanitizeArray(array $value): array {
        return array_map('self::sanitizeString', $value);
    }

    public static function sanitizeStringToArray(string $value): array {
        return self::sanitizeArray(explode(',', $value));
    }

}