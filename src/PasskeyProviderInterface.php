<?php

namespace VoltCMS\UserAccess;

interface PasskeyProviderInterface
{
    public static function getInstance(?array $config = null);

    public function exists(string $attribute, string $value): bool;

    public function create(Passkey $passkey): Passkey;

    public function read(string $attribute, string $value): Passkey;

    public function readAll(): array;

    public function find(string $attribute, string $value): array;

    public function update(Passkey $passkey): Passkey;

    public function delete(string $id);

    public function deleteAll();

}
