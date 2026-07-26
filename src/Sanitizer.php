<?php

namespace VoltCMS\UserAccess;

class Sanitizer
{
    public const REGEX_ID = '/^[a-z0-9_\-]{1,36}/';
    public const REGEX_NAME = '/^[\w\@\.\-]{1,36}/';
    // Shape of a custom (host-defined) attribute name. Deliberately close to
    // what RFC 7643 §2.1 allows for a SCIM attribute name: it must start with a
    // letter so it can never look like an array index, and it stays within the
    // characters that survive a JSON key and a PATCH path unescaped. The length
    // bound is checked separately against ATTRIBUTE_NAME_MAX_LENGTH.
    public const REGEX_ATTRIBUTE_NAME = '/^[A-Za-z][A-Za-z0-9_\-]*$/';
    public const ATTRIBUTE_NAME_MAX_LENGTH = 64;

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
