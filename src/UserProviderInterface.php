<?php

namespace VoltCMS\UserAccess;

interface UserProviderInterface
{

    public static function getInstance(array $config = null);

    public function isIdExisting(string $id): bool;

    public function isNameExisting(string $userName): bool;

    public function create(User $user): User;

    public function get(string $userName): User;

    public function getAll(): array;

    public function find(string $attributeName, string $attributeValue): array;

    public function update(User $user): User;

    public function delete(string $id);

    public function deleteAll();

}
