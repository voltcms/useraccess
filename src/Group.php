<?php

namespace VoltCMS\UserAccess;

use \Exception;
use \VoltCMS\UserAccess\Sanitizer;

// https://tools.ietf.org/html/rfc7643#section-8

class Group
{

    const REGEX = '/^[a-z0-9_\-]{1,32}/';

    private $schemas = ['urn:ietf:params:scim:schemas:core:2.0:Group'];
    private $id = '';
    private $groupName = '';
    private $displayName = '';
    private $members = [];

    //////////////////////////////////////////////////

    public function getId(): string
    {
        return $this->id;
    }
    public function setId(string $id)
    {
        $id = Sanitizer::sanitizeString($id);
        if (!preg_match(self::REGEX, $id) || strlen($id) > 32) {
            throw new Exception('EXCEPTION_INVALID_GROUP_NAME');
        }
        $this->id = $id;
    }

    public function getGroupName(): string
    {
        return $this->groupName;
    }
    public function setGroupName(string $groupName)
    {
        $groupName = Sanitizer::sanitizeString($groupName);
        if (!preg_match(self::REGEX, $groupName) || strlen($groupName) > 32) {
            throw new Exception('EXCEPTION_INVALID_GROUP_NAME');
        }
        $this->groupName = $groupName;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }
    public function setDisplayName(string $displayName)
    {
        $this->displayName = trim($displayName);
    }

    public function getMembers(): array
    {
        return $this->members;
    }
    public function addMembers(array $members)
    {
        foreach ($members as $member) {
            $this->addMember($member);
        }
    }
    public function setMembers(array $members)
    {
        $this->members = Sanitizer::sanitizeArray($members);
    }
    public function hasMember(string $member): bool
    {
        return in_array(Sanitizer::sanitizeString($member), $this->members);
    }
    public function addMember(string $member)
    {
        $member = Sanitizer::sanitizeString($member);
        if ($member !== '' && !in_array($member, $this->members)) {
            $this->members[] = $member;
        }
    }
    public function removeMember(string $member)
    {
        if (($key = array_search(Sanitizer::sanitizeString($member), $this->members)) !== false) {
            unset($this->members[$key]);
        }
    }

    public function getAttributes(): array
    {
        $attributes = [];
        $attributes['schemas'] = $this->schemas;
        $attributes['id'] = $this->id;
        $attributes['groupName'] = $this->groupName;
        $attributes['displayName'] = $this->displayName;
        $attributes['members'] = $this->members;
        return $attributes;
    }

    public function toJson(): string
    {
        return json_encode($this->getAttributes());
    }

    public function setAttributes(array $attributes)
    {
        if (array_key_exists('id', $attributes)) {
            $this->setId($attributes['id']);
        }
        if (array_key_exists('groupName', $attributes)) {
            $this->setGroupName($attributes['groupName']);
        }
        if (array_key_exists('displayName', $attributes)) {
            $this->setDisplayName($attributes['displayName']);
        }
        if (array_key_exists('members', $attributes)) {
            $this->setMembers($attributes['members']);
        }
    }

}
