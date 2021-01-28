<?php

namespace PragmaPHP\UserAccess;

// https://tools.ietf.org/html/rfc7643#section-8

class User {

    public $schemas = ['urn:ietf:params:scim:schemas:core:2.0:User'];
    public $id = '';
    public $userName = '';
    public $displayName = '';
    public $email = '';
    // "emails": [
    //     {
    //       "value": "bjensen@example.com",
    //       "type": "work",
    //       "primary": true
    //     }
    //   ]
    public $active = true;
    public $passwordHash = '';
    public $groups = [];
    // "groups": [
    //     {
    //       "value": "e9e30dba-f08f-4109-8486-d5c6a331660a",
    //       "$ref":
    // "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
    //       "display": "Tour Guides"
    //     },
    // "meta": {
    //     "resourceType": "User",
    //     "created": "2010-01-23T04:56:22Z",
    //     "lastModified": "2011-05-13T04:42:34Z",
    //     "version": "W\/\"3694e05e9dff590\"",
    //     "location":
    //      "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646"
    //   }
    public $readOnly = false;

    //////////////////////////////////////////////////

    public function __construct(?string $id, string $userName, string $displayName, string $email, bool $active, string $passwordHash, array $groups) {
        $userName = trim(strtolower($userName));
        if(!preg_match('/^[a-z0-9_\-]{1,32}/', $userName) || strlen($userName) > 32){
            throw new \Exception('EXCEPTION_INVALID_USER_NAME');
        }
        $this->userName = $userName;
        if (empty($id)) {
            $this->id = $userName;
        } else {
            $this->id = $id;
        }
        $this->displayName = $displayName;

        $email = trim(strtolower($email));
        if (!empty($email) && !filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('EXCEPTION_INVALID_EMAIL');
        }
        $this->email = trim(strtolower($email));

        $this->active = $active;
        $this->passwordHash = $passwordHash;
        $this->groups = $groups;
    }

    public static function hashPassword(string $password) {
        if (empty($password)) {
            throw new \Exception('EXCEPTION_INVALID_PASSWORD');
        }
        return \password_hash($password, PASSWORD_DEFAULT);
    }

    public function setPassword(string $password) {
        $this->passwordHash = self::hashPassword($password);
    }

    public function verifyPassword(string $password): bool {
        return \password_verify($password, $this->passwordHash);
    }

    // public function setEmail(string $email) {
    //     if (!empty($email) && !filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
    //         throw new \Exception(UserAccess::EXCEPTION_INVALID_EMAIL);
    //     }
    //     $this->email = trim(strtolower($email));
    // }

    // public function getEmails(): array {
    //     return [$this->getEmail()];
    // }

    // public function setEmails(array $emails) {
    //     if (!empty($emails)) {
    //         $this->setEmail(current($emails));
    //     }
    // }

    // public function hasGroup(string $group): bool {
    //     return in_array($group, $this->groups);
    // }

    // public function addGroup(string $group) {
    //     $this->groups[] = $group;
    // }

    // public function removeGroup(string $group) {
    //     if (($key = array_search($group, $this->groups)) !== false) {
    //         unset($this->groups[$key]);
    //     }
    // }

    public function getAttributes(): array {
        return (array) $this;
    }

    public function toJson(): string {
        return json_encode($this);
    }

    // public function setAttributes(array $attributes) {
    //     parent::setAttributes($attributes);
    //     // if (array_key_exists('userName', $attributes)) {
    //     //     $this->setUserName($attributes['userName']);
    //     // }
    //     if (array_key_exists('givenName', $attributes)) {
    //         $this->setGivenName($attributes['givenName']);
    //     }
    //     if (array_key_exists('familyName', $attributes)) {
    //         $this->setFamilyName($attributes['familyName']);
    //     }
    //     if (!empty($attributes['passwordHash'])) {
    //         $this->setPasswordHash($attributes['passwordHash']);
    //     } else if (!empty($attributes['password'])) {
    //         $this->setPassword($attributes['password']);
    //     }
    //     if (array_key_exists('email', $attributes)) {
    //         $this->setEmail($attributes['email']);
    //     }
    //     if (array_key_exists('emails', $attributes)) {
    //         $this->setEmails($attributes['emails']);
    //     }
    //     if (array_key_exists('active', $attributes)) {
    //         $this->setActive($attributes['active']);
    //     }
    //     if (array_key_exists('loginAttempts', $attributes)) {
    //         $this->setLoginAttempts($attributes['loginAttempts']);
    //     }
    //     if (array_key_exists('groups', $attributes)) {
    //         $this->setRoles($attributes['groups']);
    //     }
    //     if (array_key_exists('roles', $attributes)) {
    //         $this->setRoles($attributes['roles']);
    //     }
    // }

}