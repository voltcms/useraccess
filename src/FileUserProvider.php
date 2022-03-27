<?php

namespace PragmaPHP\UserAccess;

use \Exception;
use \PragmaPHP\FileDB\FileDB;

class FileUserProvider implements UserProviderInterface {

    protected $db;

    public function __construct(string $directory = 'data') {
        $this->db = new FileDB($directory);
    }

    public function isIdExisting(string $id): bool {
        $id = trim(strtolower($id));
        return !empty($this->db->read($id));
    }

    public function isUserNameExisting(string $userName): bool {
        return $this->isIdExisting($userName);
    }

    public function getUser(string $userName): User {
        $id = trim(strtolower($userName));
        if ($this->isIdExisting($id)) {
            return $this->documentToEntry($this->db->read($id)[0]);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function createUser(User $user): User {
        if ($this->isUserNameExisting($user->getUserName())) {
            throw new Exception('EXCEPTION_USER_ALREADY_EXIST');
        } else {
            $user->setId($user->getUserName());
            $id = $this->db->create($user->getAttributes(), $user->getUserName());
            return $user;
        }
    }

    public function getUsers(): array {
        $items = $this->db->readAll();
        return $this->documentsToEntries($items);
    }

    public function findUsers(string $attributeName, string $attributeValue): array {
        $search_key = trim($attributeName);
        $search_value = trim($attributeValue);
        $items = $this->db->read(null, [
            $attributeName => $attributeValue
        ]);
        return $this->documentsToEntries($items);
    }

    public function updateUser(User $user): User {
        if ($this->isIdExisting($user->getUserName())) {
            $this->db->update($user->getUserName(), $user->getAttributes());
            return $user;
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUser(string $id) {
        $id = trim(strtolower($id));
        if ($this->isIdExisting($id)) {
            $this->db->delete($id);
        } else {
            throw new Exception('EXCEPTION_USER_NOT_EXIST');
        }
    }

    public function deleteUsers() {
        $this->db->deleteAll();
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