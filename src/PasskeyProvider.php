<?php

namespace VoltCMS\UserAccess;

use Exception;
use VoltCMS\FileDB\FileDB;

class PasskeyProvider implements PasskeyProviderInterface
{
    private static ?self $instance = null;
    private static FileDB $db;

    // The default directory is a subdirectory, not the 'data' the user and
    // group providers fall back to: passkey documents mixed into the user
    // store would come back from UserProvider::readAll() as broken users.
    public static function getInstance(?array $config = null): self
    {
        if (self::$instance === null) {
            if (empty($config) || empty($config['directory'])) {
                $directory = 'data/passkeys';
            } else {
                $directory = $config['directory'];
            }
            self::$instance = new self();
            self::$db = new FileDB($directory);
            Utils::protectDirectory($directory);
        }
        return self::$instance;
    }

    // Whether getInstance() has run. UserProvider::delete checks it so that
    // removing a user drops their passkeys without creating a passkey store the
    // host never configured.
    public static function hasInstance(): bool
    {
        return self::$instance !== null;
    }

    private function __construct()
    {}

    private function __clone(): void
    {}

    public function __wakeup(): void
    {
        throw new Exception('Cannot unserialize Object');
    }

    public function exists(string $attribute, string $value): bool
    {
        if ($attribute === 'id') {
            $id = trim(strtolower($value));
            return !empty(self::$db->read($id));
        } else {
            return !empty($this->find($attribute, $value));
        }
    }

    public function read(string $attribute, string $value): Passkey
    {
        $value = trim($value);
        if ($attribute === 'id') {
            $id = strtolower($value);
            $result = self::$db->read($id);
            if (!empty($result)) {
                return $this->documentToEntry($result[0]);
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        } else {
            $result = $this->find($attribute, $value);
            if (count($result) === 1) {
                return $result[0];
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        }
    }

    public function create(Passkey $passkey): Passkey
    {
        return Lock::exclusive(function () use ($passkey) {
            if ($this->exists('credentialId', $passkey->getCredentialId())) {
                throw new Exception('EXCEPTION_PASSKEY_ALREADY_EXIST');
            } else {
                $id = self::$db->create($passkey->getAttributes());
                return $this->documentToEntry(self::$db->read($id)[0]);
            }
        });
    }

    public function readAll(): array
    {
        $items = self::$db->readAll();
        return $this->documentsToEntries($items);
    }

    // Exact matches only. FileDB compares case-insensitively and expands '*'
    // wildcards, but credential ids are base64url, where case is significant:
    // two different credentials can differ only in case, and sign-in must
    // never resolve one to the other.
    public function find(string $attributeName, string $attributeValue): array
    {
        $attributeName = trim($attributeName);
        $attributeValue = trim($attributeValue);
        $items = self::$db->read(null, [
            $attributeName => $attributeValue,
        ]);
        $matches = [];
        foreach ($items as $item) {
            if (is_scalar($item[$attributeName]) && (string) $item[$attributeName] === $attributeValue) {
                $matches[] = $item;
            }
        }
        return $this->documentsToEntries($matches);
    }

    public function update(Passkey $passkey): Passkey
    {
        return Lock::exclusive(function () use ($passkey) {
            if ($this->exists('id', $passkey->getId())) {
                self::$db->update($passkey->getId(), $passkey->getAttributes());
                return $passkey;
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        });
    }

    public function delete(string $id): void
    {
        $id = trim(strtolower($id));
        Lock::exclusive(function () use ($id) {
            if ($this->exists('id', $id)) {
                self::$db->delete($id);
            } else {
                throw new Exception('EXCEPTION_ENTRY_NOT_EXIST');
            }
        });
    }

    public function deleteAll(): void
    {
        Lock::exclusive(function () {
            self::$db->deleteAll();
        });
    }

    private function documentsToEntries(array $items): array
    {
        $result = [];
        foreach ($items as $item) {
            $result[] = $this->documentToEntry($item);
        }
        return $result;
    }

    private function documentToEntry(array $attributes): Passkey
    {
        $passkey = new Passkey();
        $passkey->setAttributes($attributes);
        return $passkey;
    }

}
