<?php

namespace VoltCMS\UserAccess;

use \Exception;

class User
{

    CONST RESOURCE_TYPE = 'User';
    CONST SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
    private $_id = '';
    private $_created = '';
    private $_modified = '';
    private $schemas = [self::SCHEMA];
    private $userName = '';
    private $displayName = '';
    private $familyName = '';
    private $givenName = '';
    private $email = '';
    private $active = true;
    private $passwordHash = '';
    private $loginAttempts = 0;
    private $admin = false;

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
 
    public function setUserName(string $userName)
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
 
    public function setDisplayName(string $displayName)
    {
        $this->displayName = trim($displayName);
    }

    public function getFamilyName(): string
    {
        return $this->familyName;
    }
 
    public function setFamilyName(string $familyName)
    {
        $this->familyName = trim($familyName);
    }

    public function getGivenName(): string
    {
        return $this->givenName;
    }
 
    public function setGivenName(string $givenName)
    {
        $this->givenName = trim($givenName);
    }

    public function getEmail(): string
    {
        return $this->email;
    }
 
    public function setEmail(string $email)
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
 
    public function setActive(bool $active)
    {
        $this->active = $active;
    }

    public function setPassword(string $password)
    {
        $this->passwordHash = self::hashPassword(trim($password));
    }
 
    public function setPasswordHash(string $passwordHash)
    {
        $this->passwordHash = trim($passwordHash);
    }
 
    public static function hashPassword(string $password): string
    {
        if (empty($password)) {
            throw new Exception('EXCEPTION_INVALID_PASSWORD');
        }
        return \password_hash($password, PASSWORD_DEFAULT);
    }
 
    public function verifyPassword(string $password): bool
    {
        return \password_verify(trim($password), $this->passwordHash);
    }

    public function isMemberOf(string $group): bool
    {
        $groupProvider = GroupProvider::getInstance();
        if ($groupProvider->exists('displayName', $group)) {
            $group = $groupProvider->read('displayName', $group);
            return $group->hasMember($this->_id);
        } else if ($groupProvider->exists('id', $group)) {
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

    public function setLoginAttempts(int $loginAttempts)
    {
        $this->loginAttempts = $loginAttempts;
    }

    public function isAdmin(): bool
    {
        return $this->isMemberOf('Administrators');
    }

    public function getLocation(): string
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/users/" . $this->_id;
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
        $result['meta'] = [
            'resourceType' => self::RESOURCE_TYPE,
            'created' => date(DATE_ATOM, $result['_created']),
            'lastModified' => date(DATE_ATOM, $result['_modified']),
            'version' => $etag,
            'location' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/users/" . $result['id']
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
        return $result;
    }

    public function setAttributes(array $attributes)
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
        } else if (array_key_exists('password', $attributes)) {
            $this->setPassword($attributes['password']);
        }
        if (array_key_exists('email', $attributes)) {
            $this->setEmail($attributes['email']);
        } else if (array_key_exists('emails', $attributes) && is_array($attributes['emails'])) {
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
        if (array_key_exists('_created', $attributes)) {
            $this->_created = $attributes['_created'];
        }
        if (array_key_exists('_modified', $attributes)) {
            $this->_modified = $attributes['_modified'];
        }
    }

    public function fromSCIM(array $attributes) {
        $this->setAttributes($attributes);
    }

}
