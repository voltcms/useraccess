<?php

namespace VoltCMS\UserAccess;

interface UserProviderInterface
{

    public static function getInstance(array $config = null);

    public function isIdExisting(string $id): bool;

    public function isUserNameExisting(string $userName): bool;

    public function createUser(User $user): User;

    public function getUser(string $userName): User;

    public function getUsers(): array;

    public function findUsers(string $attributeName, string $attributeValue): array;

    public function updateUser(User $user): User;

    public function deleteUser(string $id);

    public function deleteUsers();

}
