<?php

namespace VoltCMS\UserAccess;

interface GroupProviderInterface
{

    public static function getInstance(array $config = null);

    public function isIdExisting(string $id): bool;

    public function isNameExisting(string $groupName): bool;

    public function create(Group $group): Group;

    public function get(string $groupName): Group;

    public function getAll(): array;

    public function find(string $attributeName, string $attributeValue): array;

    public function update(Group $group): Group;

    public function delete(string $id);

    public function deleteAll();

}
