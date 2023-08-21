<?php

namespace VoltCMS\UserAccess;

interface GroupProviderInterface
{

    public static function getInstance(array $config = null);

    public function exists(string $attribute, string $value): bool;

    public function create(Group $group): Group;

    public function read(String $attribute, string $value): Group;

    public function readAll(): array;

    public function find(string $attribute, string $value): array;

    public function update(Group $group): Group;

    public function delete(string $id);

    public function deleteAll();

}
