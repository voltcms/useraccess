<?php

namespace VoltCMS\UserAccess;

use Exception;

class Group
{
    public const RESOURCE_TYPE = 'Group';
    public const SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
    private string $_id = '';
    // $_created / $_modified stay untyped: FileDB stores them as integer
    // timestamps but the entity initializes them to '', and a string type would
    // silently coerce the timestamps written back in getAttributes().
    private $_created = '';
    private $_modified = '';
    private array $schemas = [self::SCHEMA];
    private string $displayName = '';
    private array $members = [];

    //////////////////////////////////////////////////

    public function getId(): string
    {
        return $this->_id;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function setDisplayName(string $displayName): void
    {
        $this->displayName = trim($displayName);
    }

    public function getMembers(): array
    {
        return $this->members;
    }

    public function addMembers(array $members): void
    {
        $members = Sanitizer::sanitizeArray($members);
        foreach ($members as $member) {
            $this->addMember($member);
        }
    }

    public function setMembers(array $members): void
    {
        $this->members = [];
        $this->addMembers($members);
    }

    public function hasMember(string $member): bool
    {
        return in_array(Sanitizer::sanitizeString($member), $this->members);
    }

    public function addMember(string $member): void
    {
        if ($member === '') {
            throw new Exception('EXCEPTION_EMPTY_ID');
        }
        $userProvider = UserProvider::getInstance();
        if ($userProvider->exists('id', $member)) {
            if (!in_array($member, $this->members)) {
                $this->members[] = $member;
            }
        }
    }

    public function removeMember(string $member): void
    {
        if (($key = array_search($member, $this->members)) !== false) {
            unset($this->members[$key]);
        }
    }

    public function getAttributes(): array
    {
        $attributes = [];
        $attributes['_id'] = $this->_id;
        $attributes['_created'] = $this->_created;
        $attributes['_modified'] = $this->_modified;
        $attributes['schemas'] = $this->schemas;
        $attributes['displayName'] = $this->displayName;
        $attributes['members'] = $this->members;
        return $attributes;
    }

    public function toSCIM(bool $includeEtagLastModified = false): array
    {
        $userProvider = UserProvider::getInstance();
        $result = $this->getAttributes();
        $etag = md5(json_encode($result));
        $result['schemas'] = [self::SCHEMA];
        $result['id'] = $result['_id'];
        $members = [];
        foreach ($result['members'] as $member) {
            if ($userProvider->exists('id', $member)) {
                $user = $userProvider->read('id', $member);
                $members[] = [
                    'value' => $member,
                    'display' => $user->getDisplayName(),
                    '$ref' => $user->getLocation()
                ];
            }
        }
        $result['members'] = $members;
        $result['meta'] = [
            'resourceType' => self::RESOURCE_TYPE,
            'created' => date(DATE_ATOM, $result['_created']),
            'lastModified' => date(DATE_ATOM, $result['_modified']),
            'version' => $etag,
            'location' => (Utils::isHttps() ? 'https' : 'http') . "://$_SERVER[HTTP_HOST]" . str_replace('index.php', '', $_SERVER['SCRIPT_NAME']) . 'scim/groups/' . $result['id']
        ];
        if ($includeEtagLastModified) {
            $result['etagLastModified'] = $result['_modified'];
        }
        unset($result['_id']);
        unset($result['_created']);
        unset($result['_modified']);
        return $result;
    }

    public function setAttributes(array $attributes): void
    {
        if (array_key_exists('schemas', $attributes)) {
            $this->schemas = $attributes['schemas'];
        }
        if (array_key_exists('_id', $attributes)) {
            $this->_id = $attributes['_id'];
        }
        if (array_key_exists('displayName', $attributes)) {
            $this->setDisplayName($attributes['displayName']);
        }
        if (array_key_exists('members', $attributes)) {
            $members = [];
            if (is_array($attributes['members'])) {
                foreach ($attributes['members'] as $member) {
                    if (is_array($member)) {
                        if (array_key_exists('value', $member)) {
                            $members[] = $member['value'];
                        }
                    } else {
                        $members[] = $member;
                    }
                }
            }
            $this->setMembers($members);
        }
        if (array_key_exists('_created', $attributes)) {
            $this->_created = $attributes['_created'];
        }
        if (array_key_exists('_modified', $attributes)) {
            $this->_modified = $attributes['_modified'];
        }
    }

    public function fromSCIM(array $attributes): void
    {
        $this->setAttributes($attributes);
    }
}
