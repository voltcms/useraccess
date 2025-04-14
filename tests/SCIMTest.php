<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\SCIM;
use VoltCMS\UserAccess\UserProviderInterface;
use VoltCMS\UserAccess\GroupProviderInterface;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\Group;

class SCIMTest extends TestCase
{
    private $scim;
    private $userProviderMock;
    private $groupProviderMock;
    private $sessionAuthMock;

    protected function setUp(): void
    {
        $this->userProviderMock = $this->createMock(UserProviderInterface::class);
        $this->groupProviderMock = $this->createMock(GroupProviderInterface::class);
        $this->sessionAuthMock = $this->createMock(SessionAuth::class);

        $this->scim = new SCIM($this->userProviderMock, $this->groupProviderMock);
    }

    public function testCreateGroup()
    {
        $groupData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Test Group'
        ];

        $group = $this->createMock(Group::class);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('create')
            ->willReturn($group);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('exists')
            ->with('displayName', 'Test Group')
            ->willReturn(false);

        $this->expectOutputRegex('/"displayName":"Test Group"/');
        $this->scim->createGroup(json_encode($groupData));
    }

    public function testGetGroup()
    {
        $groupID = '1234';
        $groupData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'id' => $groupID,
            'displayName' => 'Test Group'
        ];

        $group = $this->createMock(Group::class);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('exists')
            ->with('id', $groupID)
            ->willReturn(true);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('read')
            ->with('id', $groupID)
            ->willReturn($group);

        $this->expectOutputRegex('/"id":"1234"/');
        $this->scim->getGroup($groupID);
    }

    public function testDeleteGroup()
    {
        $groupID = '1234';

        $group = $this->createMock(Group::class);
        $group->method('getDisplayName')->willReturn('Test Group');

        $this->groupProviderMock
            ->expects($this->once())
            ->method('exists')
            ->with('id', $groupID)
            ->willReturn(true);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('read')
            ->with('id', $groupID)
            ->willReturn($group);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('delete')
            ->with($groupID);

        $this->expectOutputString('');
        $this->scim->deleteGroup($groupID);
    }

    public function testPutGroup()
    {
        $groupID = '1234';
        $groupData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Updated Group'
        ];

        $group = $this->createMock(Group::class);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('exists')
            ->with('id', $groupID)
            ->willReturn(true);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('read')
            ->with('id', $groupID)
            ->willReturn($group);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('update')
            ->willReturn($group);

        $this->expectOutputRegex('/"displayName":"Updated Group"/');
        $this->scim->putGroup(json_encode($groupData), $groupID);
    }

    public function testListGroups()
    {
        $groupData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Test Group'
        ];

        $group = $this->createMock(Group::class);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('readAll')
            ->willReturn([$group]);

        $this->expectOutputRegex('/"displayName":"Test Group"/');
        $this->scim->listGroups([]);
    }
}