<?php

namespace VoltCMS\UserAccess;

use Exception;

class User
{
    public const RESOURCE_TYPE = 'User';
    public const SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
    // SCIM extension schema (RFC 7643 §3.3) under which host-defined custom
    // attributes are carried on the wire. Attributes the core User schema does
    // not define must live in an extension namespace rather than at the top
    // level, so a SCIM client can tell core fields from deployment-specific
    // ones.
    public const CUSTOM_SCHEMA = 'urn:ietf:params:scim:schemas:extension:voltcms:2.0:User';
    // Password policy. 8 is the minimum length; 72 is the byte limit of bcrypt
    // (PASSWORD_DEFAULT) — anything longer is silently truncated by the hash, so
    // it is rejected rather than accepted with a misleading tail.
    public const PASSWORD_MIN_LENGTH = 8;
    public const PASSWORD_MAX_LENGTH = 72;
    // Names a custom attribute may not take: every key getAttributes() manages
    // plus the SCIM aliases the entity understands. Without this a custom
    // attribute called "passwordHash" would ride the attribute map straight
    // into setAttributes() and overwrite managed state.
    private const RESERVED_ATTRIBUTE_NAMES = [
        '_id', '_created', '_modified', 'schemas', 'id', 'meta', 'userName',
        'displayName', 'name', 'familyName', 'givenName', 'email', 'emails',
        'active', 'password', 'passwordHash', 'loginAttempts', 'groups',
        'customAttributes',
    ];
    private string $_id = '';
    // $_created / $_modified stay untyped: FileDB stores them as integer
    // timestamps but the entity initializes them to '', and a string type would
    // silently coerce the timestamps written back in getAttributes().
    private $_created = '';
    private $_modified = '';
    private array $schemas = [self::SCHEMA];
    private string $userName = '';
    private string $displayName = '';
    private string $familyName = '';
    private string $givenName = '';
    private string $email = '';
    private bool $active = true;
    private string $passwordHash = '';
    private int $loginAttempts = 0;
    private bool $admin = false;
    /** @var array<string, scalar|null|array<int, scalar|null>> */
    private array $customAttributes = [];

    // "emails": [
    //     {
    //       "value": "bjensen@example.com",
    //       "type": "work",
    //       "primary": true
    //     }
    //   ]

    // "meta": {
    //     "resourceType": "User",
    //     "created": "2010-01-23T04:56:22Z",
    //     "lastModified": "2011-05-13T04:42:34Z",
    //     "version": "W\/\"3694e05e9dff590\"",
    //     "location":
    //      "https://example.com/Users/2819c223-7f76-453a-919d-413861904646"
    //   }

    //////////////////////////////////////////////////

    public function getId(): string
    {
        return $this->_id;
    }

    public function getUserName(): string
    {
        return $this->userName;
    }

    public function setUserName(string $userName): void
    {
        if (!preg_match(Sanitizer::REGEX_NAME, $userName)) {
            throw new Exception('EXCEPTION_INVALID_USER_NAME');
        }
        $this->userName = $userName;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function setDisplayName(string $displayName): void
    {
        $this->displayName = trim($displayName);
    }

    public function getFamilyName(): string
    {
        return $this->familyName;
    }

    public function setFamilyName(string $familyName): void
    {
        $this->familyName = trim($familyName);
    }

    public function getGivenName(): string
    {
        return $this->givenName;
    }

    public function setGivenName(string $givenName): void
    {
        $this->givenName = trim($givenName);
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): void
    {
        $email = trim(strtolower($email));
        if (!empty($email) && !filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
            throw new Exception('EXCEPTION_INVALID_EMAIL');
        }
        $this->email = $email;
    }

    public function getEmails(): array
    {
        return [$this->getEmail()];
    }

    public function getActive(): bool
    {
        return $this->active;
    }

    public function isActive(): bool
    {
        return $this->active;
    }

    public function setActive(bool $active): void
    {
        $this->active = $active;
    }

    public function setPassword(string $password): void
    {
        $this->passwordHash = self::hashPassword(trim($password));
    }

    public function setPasswordHash(string $passwordHash): void
    {
        $this->passwordHash = trim($passwordHash);
    }

    public static function hashPassword(string $password): string
    {
        self::validatePassword($password);
        return password_hash($password, PASSWORD_DEFAULT);
    }

    // Enforces the password policy. Throws EXCEPTION_INVALID_PASSWORD when the
    // (already trimmed) password is empty, shorter than PASSWORD_MIN_LENGTH, or
    // longer than PASSWORD_MAX_LENGTH bytes. setPasswordHash bypasses this on
    // purpose — it stores an already-hashed value, not a plaintext password.
    public static function validatePassword(string $password): void
    {
        $length = strlen($password);
        if ($length < self::PASSWORD_MIN_LENGTH || $length > self::PASSWORD_MAX_LENGTH) {
            throw new Exception('EXCEPTION_INVALID_PASSWORD');
        }
    }

    public function verifyPassword(string $password): bool
    {
        return password_verify(trim($password), $this->passwordHash);
    }

    public function isMemberOf(string $group): bool
    {
        $groupProvider = GroupProvider::getInstance();
        if ($groupProvider->exists('displayName', $group)) {
            $group = $groupProvider->read('displayName', $group);
            return $group->hasMember($this->_id);
        } elseif ($groupProvider->exists('id', $group)) {
            $group = $groupProvider->read('id', $group);
            return $group->hasMember($this->_id);
        } else {
            return false;
        }
    }

    public function getLoginAttempts(): int
    {
        return $this->loginAttempts;
    }

    public function setLoginAttempts(int $loginAttempts): void
    {
        $this->loginAttempts = $loginAttempts;
    }

    // Custom attributes let a host application store its own fields on a user —
    // a department, an employee number, a tenant id — without this library
    // having to know about them. They are persisted next to the core fields and
    // travel over SCIM inside the CUSTOM_SCHEMA extension object.
    /** @return array<string, scalar|null|array<int, scalar|null>> */
    public function getCustomAttributes(): array
    {
        return $this->customAttributes;
    }

    // Replaces the whole set. Later entries win over earlier ones that differ
    // only in case, since SCIM attribute names are case-insensitive.
    public function setCustomAttributes(array $customAttributes): void
    {
        $validated = [];
        foreach ($customAttributes as $name => $value) {
            $name = self::validateCustomAttributeName((string) $name);
            foreach (array_keys($validated) as $existing) {
                if (strcasecmp((string) $existing, $name) === 0) {
                    unset($validated[$existing]);
                }
            }
            $validated[$name] = self::validateCustomAttributeValue($value);
        }
        $this->customAttributes = $validated;
    }

    public function hasCustomAttribute(string $name): bool
    {
        return $this->resolveCustomAttributeName($name) !== null;
    }

    public function getCustomAttribute(string $name, mixed $default = null): mixed
    {
        $key = $this->resolveCustomAttributeName($name);
        return $key === null ? $default : $this->customAttributes[$key];
    }

    public function setCustomAttribute(string $name, mixed $value): void
    {
        $name = self::validateCustomAttributeName($name);
        $value = self::validateCustomAttributeValue($value);
        // A name that already exists under different casing is the same
        // attribute; drop it so the map never holds two spellings of one name.
        $existing = $this->resolveCustomAttributeName($name);
        if ($existing !== null && $existing !== $name) {
            unset($this->customAttributes[$existing]);
        }
        $this->customAttributes[$name] = $value;
    }

    public function removeCustomAttribute(string $name): void
    {
        $key = $this->resolveCustomAttributeName($name);
        if ($key !== null) {
            unset($this->customAttributes[$key]);
        }
    }

    public function clearCustomAttributes(): void
    {
        $this->customAttributes = [];
    }

    // Resolves a caller-supplied name to the key it is actually stored under.
    private function resolveCustomAttributeName(string $name): ?string
    {
        $name = trim($name);
        foreach (array_keys($this->customAttributes) as $key) {
            if (strcasecmp((string) $key, $name) === 0) {
                return (string) $key;
            }
        }
        return null;
    }

    private static function validateCustomAttributeName(string $name): string
    {
        $name = trim($name);
        if (strlen($name) > Sanitizer::ATTRIBUTE_NAME_MAX_LENGTH || !preg_match(Sanitizer::REGEX_ATTRIBUTE_NAME, $name)) {
            throw new Exception('EXCEPTION_INVALID_ATTRIBUTE_NAME');
        }
        foreach (self::RESERVED_ATTRIBUTE_NAMES as $reserved) {
            if (strcasecmp($reserved, $name) === 0) {
                throw new Exception('EXCEPTION_RESERVED_ATTRIBUTE_NAME');
            }
        }
        return $name;
    }

    // Values stay JSON-simple: a scalar, null, or a flat list of those. Nested
    // objects are rejected so the stored documents keep a predictable shape and
    // a custom value can never smuggle in a whole object graph.
    private static function validateCustomAttributeValue(mixed $value): mixed
    {
        if ($value === null || is_scalar($value)) {
            return $value;
        }
        if (is_array($value) && array_is_list($value)) {
            foreach ($value as $item) {
                if ($item !== null && !is_scalar($item)) {
                    throw new Exception('EXCEPTION_INVALID_ATTRIBUTE_VALUE');
                }
            }
            return $value;
        }
        throw new Exception('EXCEPTION_INVALID_ATTRIBUTE_VALUE');
    }

    public function isAdmin(): bool
    {
        return $this->isMemberOf('Administrators');
    }

    public function getLocation(): string
    {
        return (Utils::isHttps() ? 'https' : 'http') . "://$_SERVER[HTTP_HOST]" . str_replace('index.php', '', $_SERVER['SCRIPT_NAME']) . 'scim/users/' . $this->_id;
    }

    public function getAttributes(): array
    {
        $attributes = [];
        $attributes['_id'] = $this->_id;
        $attributes['_created'] = $this->_created;
        $attributes['_modified'] = $this->_modified;
        $attributes['schemas'] = $this->schemas;
        $attributes['userName'] = $this->userName;
        $attributes['displayName'] = $this->displayName;
        $attributes['familyName'] = $this->familyName;
        $attributes['givenName'] = $this->givenName;
        $attributes['email'] = $this->email;
        $attributes['active'] = $this->active;
        $attributes['passwordHash'] = $this->passwordHash;
        $attributes['loginAttempts'] = $this->loginAttempts;
        $attributes['customAttributes'] = $this->customAttributes;
        return $attributes;
    }

    public function toSCIM(bool $includeEtagLastModified = false): array
    {
        $result = $this->getAttributes();
        $etag = md5(json_encode($result));
        $result['schemas'] = [self::SCHEMA];
        $result['id'] = $result['_id'];
        $result['name'] = [
            'familyName' => $result['familyName'],
            'givenName' => $result['givenName']
        ];
        $result['emails'] = [[
            'type' => 'work',
            'primary' => 'true',
            'value' => $result['email']
        ]];
        // Custom attributes are only advertised when there are any: an empty
        // extension object would make every response claim a schema it does not
        // actually carry.
        if (!empty($result['customAttributes'])) {
            $result['schemas'][] = self::CUSTOM_SCHEMA;
            $result[self::CUSTOM_SCHEMA] = $result['customAttributes'];
        }
        $result['meta'] = [
            'resourceType' => self::RESOURCE_TYPE,
            'created' => date(DATE_ATOM, $result['_created']),
            'lastModified' => date(DATE_ATOM, $result['_modified']),
            'version' => $etag,
            'location' => (Utils::isHttps() ? 'https' : 'http') . "://$_SERVER[HTTP_HOST]" . str_replace('index.php', '', $_SERVER['SCRIPT_NAME']) . 'scim/users/' . $result['id']
        ];
        if ($includeEtagLastModified) {
            $result['etagLastModified'] = $result['_modified'];
        }
        unset($result['_id']);
        unset($result['_created']);
        unset($result['_modified']);
        unset($result['familyName']);
        unset($result['givenName']);
        unset($result['email']);
        unset($result['passwordHash']);
        unset($result['loginAttempts']);
        unset($result['customAttributes']);
        return $result;
    }

    public function setAttributes(array $attributes): void
    {
        if (array_key_exists('schemas', $attributes)) {
            $this->schemas = $attributes['schemas'];
        }
        if (array_key_exists('_id', $attributes)) {
            $this->_id = $attributes['_id'];
        }
        if (array_key_exists('userName', $attributes)) {
            $this->setUserName($attributes['userName']);
        }
        if (array_key_exists('displayName', $attributes)) {
            $this->setDisplayName($attributes['displayName']);
        }
        if (array_key_exists('familyName', $attributes)) {
            $this->setFamilyName($attributes['familyName']);
        }
        if (array_key_exists('givenName', $attributes)) {
            $this->setGivenName($attributes['givenName']);
        }
        if (array_key_exists('name', $attributes) && is_array($attributes['name'])) {

            if (array_key_exists('familyName', $attributes['name'])) {
                $this->setFamilyName($attributes['name']['familyName']);
            }
            if (array_key_exists('givenName', $attributes['name'])) {
                $this->setGivenName($attributes['name']['givenName']);
            }
        }
        if (array_key_exists('passwordHash', $attributes)) {
            $this->setPasswordHash($attributes['passwordHash']);
        } elseif (array_key_exists('password', $attributes)) {
            $this->setPassword($attributes['password']);
        }
        if (array_key_exists('email', $attributes)) {
            $this->setEmail($attributes['email']);
        } elseif (array_key_exists('emails', $attributes) && is_array($attributes['emails'])) {
            if ($attributes['emails'] && count($attributes['emails']) > 0) {
                $this->setEmail($attributes['emails'][0]['value']);
            }
        }
        if (array_key_exists('active', $attributes)) {
            $this->setActive($attributes['active']);
        }
        if (array_key_exists('loginAttempts', $attributes)) {
            $this->setLoginAttempts($attributes['loginAttempts']);
        }
        // 'customAttributes' is the stored shape (FileDB documents); the
        // CUSTOM_SCHEMA key is the same map as it arrives over SCIM. Either one
        // replaces the whole set; omitting both leaves the stored attributes
        // untouched, so a PUT that says nothing about them does not wipe them.
        if (array_key_exists('customAttributes', $attributes)) {
            if (!is_array($attributes['customAttributes'])) {
                throw new Exception('EXCEPTION_INVALID_ATTRIBUTE_VALUE');
            }
            $this->setCustomAttributes($attributes['customAttributes']);
        }
        if (array_key_exists(self::CUSTOM_SCHEMA, $attributes)) {
            if (!is_array($attributes[self::CUSTOM_SCHEMA])) {
                throw new Exception('EXCEPTION_INVALID_ATTRIBUTE_VALUE');
            }
            $this->setCustomAttributes($attributes[self::CUSTOM_SCHEMA]);
        }
        if (array_key_exists('_created', $attributes)) {
            $this->_created = $attributes['_created'];
        }
        if (array_key_exists('_modified', $attributes)) {
            $this->_modified = $attributes['_modified'];
        }
    }

    public function fromSCIM(array $attributes): void
    {
        $this->setAttributes($attributes);
    }

}
