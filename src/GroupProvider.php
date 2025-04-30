<?php

namespace VoltCMS\UserAccess;

use \Exception;
use \VoltCMS\FileDB\FileDB;

class GroupProvider implements GroupProviderInterface 
{

    private static $instance = null;
    private static $db;

    public static function getInstance(?array $config = null)
    {
        if (self::$instance === null) {
            if (empty($config) || empty($config['directory'])) {
                $directory = 'data';
            } else {
                $directory = $config['directory'];
            }
            self::$instance = new static();
            self::$db = new FileDB($directory);
            self::$instance->createAdminGroup();
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

    public function exists(string $attribute, string $value): bool
    {
        if ($attribute == 'id') {
            $id = trim(strtolower($value));
            return !empty(self::$db->read($id));
        } else {
            return !empty($this->find($attribute, $value));
        }
    }

    public function read(string $attribute, string $value): Group
    {
        if ($attribute == 'id') {
            $id = trim(strtolower($value));
            if ($this->exists($attribute, $id)) {
                return $this->documentToEntry(self::$db->read($id)[0]);
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        } else {
            if ($this->exists($attribute, $value)) {
                $result = $this->find($attribute, $value);
                if (count($result) == 1) {
                    return $result[0];
                } else {
                    throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
                }
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        }
    }

    public function create(Group $group): Group
    {
        if ($this->exists('displayName', $group->getDisplayName())) {
            throw new Exception('EXCEPTION_GROUP_ALREADY_EXIST');
        } else {
            $id = self::$db->create($group->getAttributes());
            return $this->documentToEntry(self::$db->read($id)[0]);
        }
    }

    public function readAll(): array
    {
        $items = self::$db->readAll();
        return $this->documentsToEntries($items);
    }

    public function find(string $attributeName, string $attributeValue): array
    {
        $attributeName = trim($attributeName);
        $attributeValue = trim($attributeValue);
        $items = self::$db->read(null, [
            $attributeName => $attributeValue,
        ]);
        return $this->documentsToEntries($items);
    }

    public function update(Group $group): Group
    {
        if ($this->exists('id', $group->getId())) {
            self::$db->update($group->getId(), $group->getAttributes());
            return $group;
        } else {
            throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
        }
    }

    public function delete(string $id)
    {
        $id = trim(strtolower($id));
        if ($this->exists('id', $id)) {
            self::$db->delete($id);
        } else {
            throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
        }
    }

    public function deleteAll()
    {
        self::$db->deleteAll();
        self::createAdminGroup();
    }

    private function createAdminGroup() {
        if (!self::$instance->exists('displayName', 'Administrators')) {
            $administrators = new Group();
            $administrators->setDisplayName('Administrators');
            self::$instance->create($administrators);
        }
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
