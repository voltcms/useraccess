<?php

namespace PragmaPHP\UserAccess;

// https://tools.ietf.org/html/rfc7643#section-8

class User {

    private $schemas = ['urn:ietf:params:scim:schemas:core:2.0:User'];
    private $id = '';
    private $userName = '';
    private $displayName = '';
    private $email = '';
    private $active = true;
    private $passwordHash = '';
    private $groups = [];
    private $loginAttempts = 0;

    // "emails": [
    //     {
    //       "value": "bjensen@example.com",
    //       "type": "work",
    //       "primary": true
    //     }
    //   ]

    // "groups": [
    //     {
    //       "value": "e9e30dba-f08f-4109-8486-d5c6a331660a",
    //       "$ref":
    // "https://example.com/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
    //       "display": "Tour Guides"
    //     }
    //   ]

    // "meta": {
    //     "resourceType": "User",
    //     "created": "2010-01-23T04:56:22Z",
    //     "lastModified": "2011-05-13T04:42:34Z",
    //     "version": "W\/\"3694e05e9dff590\"",
    //     "location":
    //      "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646"
    //   }

    //////////////////////////////////////////////////

    public function getId() {
        return $this->id;
    }
    public function setId($id) {
        $id = trim(strtolower($id));
        if(!preg_match('/^[a-z0-9_\-]{1,32}/', $id) || strlen($id) > 32){
            throw new \Exception('EXCEPTION_INVALID_USER_NAME');
        }
        $this->id = trim(strtolower($id));
    }

    public function getUserName() {
        return $this->userName;
    }
    public function setUserName($userName) {
        $userName = trim(strtolower($userName));
        if(!preg_match('/^[a-z0-9_\-]{1,32}/', $userName) || strlen($userName) > 32){
            throw new \Exception('EXCEPTION_INVALID_USER_NAME');
        }
        $this->userName = $userName;
    }

    public function getDisplayName() {
        return $this->displayName;
    }
    public function setDisplayName($displayName) {
        $this->displayName = trim($displayName);
    }

    public function getEmail() {
        return $this->email;
    }
    public function setEmail($email) {
        $email = trim(strtolower($email));
        if (!empty($email) && !filter_var(trim($email), FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('EXCEPTION_INVALID_EMAIL');
        }
        $this->email = $email;
    }
    public function getEmails(): array {
        return [$this->getEmail()];
    }
    public function setEmails(array $emails) {
        if (!empty($emails)) {
            $this->setEmail(current($emails));
        }
    }

    public function getActive() {
        return $this->active;
    }
    public function isActive() {
        return $this->active;
    }
    public function setActive($active) {
        $this->active = $active;
    }

    public function setPassword(string $password) {
        $this->passwordHash = self::hashPassword(trim($password));
    }
    public function setPasswordHash(string $passwordHash) {
        $this->passwordHash = trim($passwordHash);
    }
    public static function hashPassword(string $password) {
        if (empty($password)) {
            throw new \Exception('EXCEPTION_INVALID_PASSWORD');
        }
        return \password_hash($password, PASSWORD_DEFAULT);
    }
    public function verifyPassword(string $password): bool {
        return \password_verify(trim($password), $this->passwordHash);
    }

    public function getGroups() {
        return $this->groups;
    }
    public function setGroups($groups) {
        $this->groups = $groups;
    }
    public function hasGroup(string $group): bool {
        return in_array($group, $this->groups);
    }
    public function addGroup(string $group) {
        $this->groups[] = $group;
    }
    public function removeGroup(string $group) {
        if (($key = array_search($group, $this->groups)) !== false) {
            unset($this->groups[$key]);
        }
    }

    public function getLoginAttempts() {
        return $this->loginAttempts;
    }
    public function setLoginAttempts($loginAttempts) {
        $this->loginAttempts = $loginAttempts;
    }

    public function getAttributes(): array {
        $attributes = [];
        $attributes['schemas'] = $this->schemas;
        $attributes['id'] = $this->id;
        $attributes['userName'] = $this->userName;
        $attributes['displayName'] = $this->displayName;
        $attributes['email'] = $this->email;
        $attributes['active'] = $this->active;
        $attributes['passwordHash'] = $this->passwordHash;
        $attributes['groups'] = $this->groups;
        $attributes['loginAttempts'] = $this->loginAttempts;
        return $attributes;
    }

    public function toJson(): string {
        return json_encode($this->getAttributes());
    }

    public function setAttributes(array $attributes) {
        if (array_key_exists('id', $attributes)) {
            $this->setId($attributes['id']);
        }
        if (array_key_exists('userName', $attributes)) {
            $this->setUserName($attributes['userName']);
        }
        if (array_key_exists('displayName', $attributes)) {
            $this->setDisplayName($attributes['displayName']);
        }
        if (array_key_exists('passwordHash', $attributes)) {
            $this->setPasswordHash($attributes['passwordHash']);
        } else if (array_key_exists('password', $attributes)) {
            $this->setPassword($attributes['password']);
        }
        if (array_key_exists('email', $attributes)) {
            $this->setEmail($attributes['email']);
        } else if (array_key_exists('emails', $attributes)) {
            $this->setEmails($attributes['emails']);
        }
        if (array_key_exists('active', $attributes)) {
            $this->setActive($attributes['active']);
        }
        if (array_key_exists('loginAttempts', $attributes)) {
            $this->setLoginAttempts($attributes['loginAttempts']);
        }
        if (array_key_exists('groups', $attributes)) {
            $this->setGroups($attributes['groups']);
        }
    }

}