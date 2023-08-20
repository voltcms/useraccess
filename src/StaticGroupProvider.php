<?php

namespace VoltCMS\UserAccess;

use \Exception;

class StaticGroupProvider implements GroupProviderInterface
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

    public function isNameExisting(string $groupName): bool
    {
        return $this->isIdExisting($groupName);
    }

    public function get(string $groupName): Group
    {
        $id = trim(strtolower($groupName));
        if ($this->isIdExisting($groupName)) {
            return $this->entries[$groupName];
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function create(Group $group): Group
    {
        if ($this->isNameExisting($group->getGroupName())) {
            throw new Exception('EXCEPTION_GROUP_ALREADY_EXIST');
        } else {
            $group->setId($group->getGroupName());
            $this->entries[$group->getId()] = $group;
            return $group;
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

    public function update(Group $group): Group
    {
        if ($this->isIdExisting($group->getGroupName())) {
            $group->setId($group->getGroupName());
            $this->entries[$group->getId()] = $group;
            return $group;
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function delete(string $id)
    {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            unset($this->entries[$id]);
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function deleteAll()
    {
        $this->entries = [];
    }

}
