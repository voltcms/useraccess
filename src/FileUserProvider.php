<?php

namespace PragmaPHP\UserAccess;

use \Exception;
use \PragmaPHP\FileDB\FileDB;

class FileUserProvider implements UserProviderInterface {

    private static $instance = null;
    private static $db;

    public static function getInstance(?array $config): static {
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

    private function __construct() {}

    private function __clone(){}

    public function __wakeup() {
        throw new Exception("Cannot unserialize Object");
    }

    public function isIdExisting(string $id): bool {
        $id = trim(strtolower($id));
        return !empty(self::$db->read($id));
    }

    public function isUserNameExisting(string $userName): bool {
        return $this->isIdExisting($userName);
    }

    public function getUser(string $userName): User {
        $id = trim(strtolower($userName));
        if ($this->isIdExisting($id)) {
            return $this->documentToEntry(self::$db->read($id)[0]);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function createUser(User $user): User {
        if ($this->isUserNameExisting($user->getUserName())) {
            throw new Exception('EXCEPTION_USER_ALREADY_EXIST');
        } else if (!empty($user->getEmail()) && !empty($this->findUsers('email', $user->getEmail()))) {
            throw new Exception('EXCEPTION_DUPLICATE_EMAIL');
        } else {
            $user->setId($user->getUserName());
            $id = self::$db->create($user->getUserName(), $user->getAttributes());
            return $user;
        }
    }

    public function getUsers(): array {
        $items = self::$db->readAll();
        return $this->documentsToEntries($items);
    }

    public function findUsers(string $attributeName, string $attributeValue): array {
        $search_key = trim($attributeName);
        $search_value = trim($attributeValue);
        $items = self::$db->read(null, [
            $attributeName => $attributeValue
        ]);
        return $this->documentsToEntries($items);
    }

    public function updateUser(User $user): User {
        if ($this->isIdExisting($user->getUserName())) {
            if (!empty($user->getEmail())) {
                $items = $this->findUsers('email', $user->getEmail());
                if (!empty($items) && $items[0]->getUserName() != $user->getUserName()) {
                    throw new Exception('EXCEPTION_DUPLICATE_EMAIL');
                }
            }
            self::$db->update($user->getUserName(), $user->getAttributes());
            return $user;
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUser(string $id) {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            self::$db->delete($id);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUsers() {
        self::$db->deleteAll();
    }

    private function documentsToEntries(array $items): array {
        $result = [];
        foreach($items as $item){
            $result[] = $this->documentToEntry($item);
        }
        return $result;
    }

    private function documentToEntry(array $attributes): User {
        $user = new User();
        $user->setAttributes($attributes);
        return $user;
    }

}
