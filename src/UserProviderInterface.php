<?php

namespace VoltCMS\UserAccess;

interface UserProviderInterface
{

    public static function getInstance(array $config = null);

    public function exists(string $attribute, string $value): bool;

    public function create(User $user): User;

    public function read(String $attribute, string $value): User;

    public function readAll(): array;

    public function find(string $attribute, string $value): array;

    public function update(User $user): User;

    public function delete(string $id);

    public function deleteAll();

}
