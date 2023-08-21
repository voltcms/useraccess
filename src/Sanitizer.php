<?php

namespace VoltCMS\UserAccess;

class Sanitizer
{

    public const REGEX_ID = '/^[a-z0-9_\-]{1,36}/';
    public const REGEX_NAME = '/^[\w@._\-]{1,36}/';

    public static function sanitizeString(string $value): string
    {
        $value = trim($value);
        $value = strtolower($value);
        $value = preg_replace('/\s+/', '-', $value);
        $value = preg_replace('/[^a-z0-9_\-]+/', '', $value);
        return $value;
    }

    public static function sanitizeArray(array $value): array
    {
        return array_map('\\VoltCMS\\UserAccess\\Sanitizer::sanitizeString', $value);
    }

    public static function sanitizeStringToArray(string $value): array
    {
        return self::sanitizeArray(explode(',', $value));
    }

}
