<?php

namespace PragmaPHP\UserAccess;

class Sanitizer {

    public static function sanitizeString($value) {
        $value = trim($value);
        $value = strtolower($value);
        $value = preg_replace('/\s+/', '-', $value);
        $value = preg_replace('/[^a-z0-9_\-]+/', '', $value);
        return $value;
    }

    public static function sanitizeStringToArray($value) {
        array_map('self::sanitizeString', explode(',', $value)),
    }

}