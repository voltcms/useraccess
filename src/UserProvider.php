<?php

namespace VoltCMS\UserAccess;

use \Exception;
use \VoltCMS\FileDB\FileDB;

class UserProvider implements UserProviderInterface
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

    public function read(string $attribute, string $value): User
    {
        $value = trim($value);
        if ($attribute == 'id') {
            $id = strtolower($value);
            $result = self::$db->read($id);
            if (!empty($result)) {
                return $this->documentToEntry($result[0]);
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        } else {
            $result = $this->find($attribute, $value);
            if (count($result) == 1) {
                return $result[0];
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        }
    }

    public function create(User $user): User
    {
        if ($this->exists('userName', $user->getUserName())) {
            throw new Exception('EXCEPTION_USER_ALREADY_EXIST');
        } else if (!empty($user->getEmail()) && !empty($this->find('email', $user->getEmail()))) {
            throw new Exception('EXCEPTION_DUPLICATE_EMAIL');
        } else {
            $id = self::$db->create($user->getAttributes());
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

    public function update(User $user): User
    {
        if ($this->exists('id', $user->getId())) {
            if (!empty($user->getEmail())) {
                $items = $this->find('email', $user->getEmail());
                if (!empty($items) && $items[0]->getId() != $user->getId()) {
                    throw new Exception('EXCEPTION_DUPLICATE_EMAIL');
                }
            }
            self::$db->update($user->getId(), $user->getAttributes());
            return $user;
        } else {
            throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
        }
    }

    public function delete(string $id)
    {
        // todo delete user membership of groups
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
    }

    private function documentsToEntries(array $items): array
    {
        $result = [];
        foreach ($items as $item) {
            $result[] = $this->documentToEntry($item);
        }
        return $result;
    }

    private function documentToEntry(array $attributes): User
    {
        $user = new User();
        $user->setAttributes($attributes);
        return $user;
    }

}
