<?php

namespace VoltCMS\UserAccess;

use \Exception;

class StaticUserProvider implements UserProviderInterface
{

    private static $instance = null;

    private $entries = [];

    public static function getInstance(array $config = null)
    {
        if (self::$instance === null) {
            self::$instance = new static();
        }
        return self::$instance;
    }

    private function __construct()
    {}

    private function __clone()
    {}

    public function __wakeup()
    {
        throw new Exception("Cannot unserialize Object");
    }

    public function isIdExisting(string $id): bool
    {
        $id = trim(strtolower($id));
        if (isset($this->entries[$id])) {
            return true;
        } else {
            return false;
        }
    }

    public function isNameExisting(string $userName): bool
    {
        return $this->isIdExisting($userName);
    }

    public function get(string $userName): User
    {
        $id = trim(strtolower($userName));
        if ($this->isIdExisting($userName)) {
            return $this->entries[$userName];
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function create(User $user): User
    {
        if ($this->isNameExisting($user->getUserName())) {
            throw new Exception('EXCEPTION_USER_ALREADY_EXIST');
        } else if (!empty($user->getEmail()) && !empty($this->find('email', $user->getEmail()))) {
            throw new Exception('EXCEPTION_DUPLICATE_EMAIL');
        } else {
            $user->setId($user->getUserName());
            $this->entries[$user->getId()] = $user;
            return $user;
        }
    }

    public function getAll(): array
    {
        return $this->entries;
    }

    public function find(string $search_key, string $search_value): array
    {
        $search_key = trim($search_key);
        $search_value = trim($search_value);
        $result = [];
        foreach ($this->entries as $entry) {
            $attributes = $entry->getAttributes();
            if (array_key_exists($search_key, $attributes)) {
                if (str_starts_with($search_value, '*') && str_ends_with($search_value, '*') && strlen($search_value) > 3) {
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

    public function update(User $user): User
    {
        if ($this->isIdExisting($user->getUserName())) {
            $user->setId($user->getUserName());
            $this->entries[$user->getId()] = $user;
            return $user;
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function delete(string $id)
    {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            unset($this->entries[$id]);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteAll()
    {
        $this->entries = [];
    }

}
