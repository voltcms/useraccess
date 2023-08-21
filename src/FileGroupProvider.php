<?php

namespace VoltCMS\UserAccess;

use \Exception;
use \VoltCMS\FileDB\FileDB;
use \VoltCMS\Uuid\Uuid;

class FileGroupProvider implements GroupProviderInterface
{

    private static $instance = null;
    private static $db;

    public static function getInstance(array $config = null)
    {
        if (self::$instance === null) {
            if (empty($config) || empty($config['directory'])) {
                $directory = 'data';
            } else {
                $directory = $config['directory'];
            }
            self::$instance = new static();
            self::$db = new FileDB($directory);
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
        return !empty(self::$db->read($id));
    }

    public function isNameExisting(string $groupName): bool
    {
        return $this->isIdExisting($groupName);
    }

    public function get(string $groupName): Group
    {
        $id = trim(strtolower($groupName));
        if ($this->isIdExisting($id)) {
            return $this->documentToEntry(self::$db->read($id)[0]);
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function create(Group $group): Group
    {
        if ($this->isNameExisting($group->getGroupName())) {
            throw new Exception('EXCEPTION_GROUP_ALREADY_EXIST');
        } else {
            if (!$group->getId()) {
                $group->setId(Uuid::generate());
            }
            $id = self::$db->create($group->getGroupName(), $group->getAttributes());
            return $group;
        }
    }

    public function getAll(): array
    {
        $items = self::$db->readAll();
        return $this->documentsToEntries($items);
    }

    public function find(string $attributeName, string $attributeValue): array
    {
        $search_key = trim($attributeName);
        $search_value = trim($attributeValue);
        $items = self::$db->read(null, [
            $attributeName => $attributeValue,
        ]);
        return $this->documentsToEntries($items);
    }

    public function update(Group $group): Group
    {
        if ($this->isIdExisting($group->getGroupName())) {
            self::$db->update($group->getGroupName(), $group->getAttributes());
            return $group;
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function delete(string $id)
    {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            self::$db->delete($id);
        } else {
            throw new Exception('EXCEPTION_GROUP_NOT_EXIST');
        }
    }

    public function deleteAll()
    {
        self::$db->deleteAll();
    }

    private function documentsToEntries(array $items): array
    {
        $result = [];
        foreach ($items as $item) {
            $result[] = $this->documentToEntry($item);
        }
        return $result;
    }

    private function documentToEntry(array $attributes): Group
    {
        $group = new Group();
        $group->setAttributes($attributes);
        return $group;
    }

}
