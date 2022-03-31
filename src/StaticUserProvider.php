<?php

namespace PragmaPHP\UserAccess;

use \Exception;

class StaticUserProvider implements UserProviderInterface {

    private static $instance = null;

    private $entries = [];

    public static function getInstance(array $config = null): static {
        if (self::$instance === null) {
            self::$instance = new static();
        }
        return self::$instance;
    }

    private function __construct() {}

    private function __clone(){}

    public function __wakeup() {
        throw new Exception("Cannot unserialize Object");
    }

    public function isIdExisting(string $id): bool {
        $id = trim(strtolower($id));
        if (isset($this->entries[$id])) {
            return true;        
        } else {
            return false;
        }
    }

    public function isUserNameExisting(string $userName): bool {
        return $this->isIdExisting($userName);
    }

    public function getUser(string $userName): User {
        $id = trim(strtolower($userName));
        if ($this->isIdExisting($userName)) {
            return $this->entries[$userName];
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function createUser(User $user): User {
        if ($this->isUserNameExisting($user->getUserName())) {
            throw new Exception('EXCEPTION_USER_ALREADY_EXIST');
        } else {
            $user->setId($user->getUserName());
            $this->entries[$user->getId()] = $user;
            return $user;
        }
    }

    public function getUsers(): array {
        return $this->entries;
    }

    public function findUsers(string $search_key, string $search_value): array {
        $search_key = trim($search_key);
        $search_value = trim($search_value);
        $result = [];
        foreach($this->entries as $entry){
            $attributes = $entry->getAttributes();
            if (array_key_exists($search_key, $attributes)) {
                if (self::startsWith($search_value, '*') && self::endsWith($search_value, '*') && strlen($search_value) > 3) {
                    if (stripos($attributes[$search_key], substr($search_value, 1, -1)) !== false) {
                        $result[] = $entry;
                    }
                } else {
                    if (strcasecmp($attributes[$search_key], $search_value) === 0) {
                        $result[] = $entry;
                    }
                }
            }
        }
        return $result;
    }

    public function updateUser(User $user): User {
        if ($this->isIdExisting($user->getUserName())) {
            $user->setId($user->getUserName());
            $this->entries[$user->getId()] = $user;
            return $user;
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUser(string $id) {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            unset($this->entries[$id]);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUsers() {
        $this->entries = [];
    }

    //////////////////////////////////////////////////

    private static function startsWith($haystack, $needle) {
        return substr_compare($haystack, $needle, 0, strlen($needle)) === 0;
    }

    private static function endsWith($haystack, $needle) {
        return substr_compare($haystack, $needle, -strlen($needle)) === 0;
    }

}