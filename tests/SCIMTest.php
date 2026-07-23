<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\SCIM;
use VoltCMS\UserAccess\UserProviderInterface;
use VoltCMS\UserAccess\GroupProviderInterface;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\Group;
use VoltCMS\UserAccess\User;

class SCIMTest extends TestCase
{
    private $scim;
    private $userProviderMock;
    private $groupProviderMock;

    protected function setUp(): void
    {
        $this->userProviderMock = $this->createMock(UserProviderInterface::class);
        $this->groupProviderMock = $this->createMock(GroupProviderInterface::class);

        $this->scim = new SCIM($this->userProviderMock, $this->groupProviderMock);
    }

    protected function tearDown(): void
    {
        // SCIM's constructor initializes the SessionAuth singleton with these
        // mock providers. Reset it so the mocks don't leak into other tests
        // (e.g. UserProviderTest) that build SessionAuth with real providers.
        $instance = new \ReflectionProperty(SessionAuth::class, 'instance');
        $instance->setAccessible(true);
        $instance->setValue(null, null);
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

    public function testCreateGroupWritesAuditEntry()
    {
        $dir = sys_get_temp_dir() . '/ua_scim_audit_' . uniqid();
        $audit = new \VoltCMS\UserAccess\AuditLog($dir);
        $this->scim->setAuditLog($audit);

        $groupData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Audited Group'
        ];

        $group = $this->createMock(Group::class);
        $group->method('toSCIM')->willReturn($groupData);
        $group->method('getId')->willReturn('group-uuid');
        $group->method('getDisplayName')->willReturn('Audited Group');

        $this->groupProviderMock->method('exists')->willReturn(false);
        $this->groupProviderMock->expects($this->once())->method('create')->willReturn($group);

        $this->expectOutputRegex('/"displayName":"Audited Group"/');
        $this->scim->createGroup(json_encode($groupData));

        $entries = array_values(array_filter(explode("\n", file_get_contents($audit->getFile()))));
        $this->assertCount(1, $entries);
        $entry = json_decode($entries[0], true);
        $this->assertSame('group.create', $entry['action']);
        $this->assertSame('Group', $entry['targetType']);
        $this->assertSame('group-uuid', $entry['targetId']);
        $this->assertSame('Audited Group', $entry['target']);
        $this->assertSame('success', $entry['outcome']);

        @unlink($audit->getFile());
        @unlink($dir . '/index.html');
        @unlink($dir . '/.htaccess');
        @rmdir($dir);
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
            ->method('read')
            ->with('id', $groupID)
            ->willReturn($group);

        $this->groupProviderMock
            ->expects($this->once())
            ->method('exists')
            ->with('displayName', 'Updated Group')
            ->willReturn(false);

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

    public function testPatchUserReplaceDisplayName()
    {
        $userID = '11111111-1111-1111-1111-111111111111';
        $userData = [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'id' => $userID,
            'displayName' => 'Patched Name',
        ];

        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setDisplayName')->with('Patched Name');
        $user->method('toSCIM')->willReturn($userData);

        $this->userProviderMock->expects($this->once())->method('exists')->with('id', $userID)->willReturn(true);
        $this->userProviderMock->expects($this->once())->method('read')->with('id', $userID)->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'path' => 'displayName', 'value' => 'Patched Name'],
            ],
        ]);

        $this->expectOutputRegex('/"displayName":"Patched Name"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserReplaceWithoutPathAppliesEachAttribute()
    {
        $userID = '22222222-2222-2222-2222-222222222222';
        $userData = ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'], 'id' => $userID];

        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setDisplayName')->with('Multi');
        $user->expects($this->once())->method('setActive')->with(true);
        $user->method('toSCIM')->willReturn($userData);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'value' => ['displayName' => 'Multi', 'active' => true]],
            ],
        ]);

        $this->expectOutputRegex('/"id":"22222222-2222-2222-2222-222222222222"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchGroupAddMember()
    {
        $groupID = '33333333-3333-3333-3333-333333333333';
        $memberID = '44444444-4444-4444-4444-444444444444';
        $groupData = ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'], 'id' => $groupID];

        $group = $this->createMock(Group::class);
        $group->expects($this->once())->method('addMember')->with($memberID);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock->expects($this->once())->method('exists')->with('id', $groupID)->willReturn(true);
        $this->groupProviderMock->expects($this->once())->method('read')->with('id', $groupID)->willReturn($group);
        $this->groupProviderMock->expects($this->once())->method('update')->willReturn($group);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'add', 'path' => 'members', 'value' => [['value' => $memberID]]],
            ],
        ]);

        $this->expectOutputRegex('/"id":"33333333-3333-3333-3333-333333333333"/');
        $this->scim->patchGroup($body, $groupID);
    }

    public function testPatchGroupRemoveMemberByFilterPath()
    {
        $groupID = '55555555-5555-5555-5555-555555555555';
        $memberID = '66666666-6666-6666-6666-666666666666';
        $groupData = ['schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'], 'id' => $groupID];

        $group = $this->createMock(Group::class);
        $group->expects($this->once())->method('removeMember')->with($memberID);
        $group->method('toSCIM')->willReturn($groupData);

        $this->groupProviderMock->method('exists')->willReturn(true);
        $this->groupProviderMock->method('read')->willReturn($group);
        $this->groupProviderMock->expects($this->once())->method('update')->willReturn($group);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'remove', 'path' => 'members[value eq "' . $memberID . '"]'],
            ],
        ]);

        $this->expectOutputRegex('/"id":"55555555-5555-5555-5555-555555555555"/');
        $this->scim->patchGroup($body, $groupID);
    }

    public function testListUsersPaginationSlicesResults()
    {
        $users = [];
        foreach (['user-1', 'user-2', 'user-3'] as $id) {
            $stub = $this->createStub(User::class);
            $stub->method('toSCIM')->willReturn(['id' => $id]);
            $users[] = $stub;
        }
        $this->userProviderMock->expects($this->once())->method('readAll')->willReturn($users);

        ob_start();
        $this->scim->listUsers(['startIndex' => 2, 'count' => 1]);
        $out = ob_get_clean();

        $this->assertStringContainsString('"totalResults":3', $out);
        $this->assertStringContainsString('"startIndex":2', $out);
        $this->assertStringContainsString('"itemsPerPage":1', $out);
        $this->assertStringContainsString('"id":"user-2"', $out);
        $this->assertStringNotContainsString('"id":"user-1"', $out);
        $this->assertStringNotContainsString('"id":"user-3"', $out);
    }

    public function testListGroupsFilterUsesProviderFind()
    {
        $group = $this->createStub(Group::class);
        $group->method('toSCIM')->willReturn(['id' => 'group-x', 'displayName' => 'Admins']);

        $this->groupProviderMock->expects($this->once())->method('find')->with('displayName', 'Admins')->willReturn([$group]);
        $this->groupProviderMock->expects($this->never())->method('readAll');

        ob_start();
        $this->scim->listGroups(['filter' => 'displayName eq "Admins"']);
        $out = ob_get_clean();

        $this->assertStringContainsString('"totalResults":1', $out);
        $this->assertStringContainsString('"id":"group-x"', $out);
    }

    public function testServiceProviderConfigDiscovery()
    {
        ob_start();
        $this->scim->showServiceProviderConfig();
        $out = ob_get_clean();

        $this->assertStringContainsString('"patch":{"supported":true}', $out);
        $this->assertStringContainsString('"sort":{"supported":false}', $out);
        $this->assertStringContainsString('"type":"httpbasic"', $out);
        $this->assertStringContainsString('urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig', $out);
    }

    public function testResourceTypesListAndSingle()
    {
        ob_start();
        $this->scim->showResourceTypes(null);
        $list = ob_get_clean();
        $this->assertStringContainsString('urn:ietf:params:scim:api:messages:2.0:ListResponse', $list);
        $this->assertStringContainsString('"id":"User"', $list);
        $this->assertStringContainsString('"id":"Group"', $list);

        ob_start();
        $this->scim->showResourceTypes('User');
        $single = ob_get_clean();
        $this->assertStringContainsString('"endpoint":"/scim/users"', $single);
        $this->assertStringContainsString('urn:ietf:params:scim:schemas:core:2.0:User', $single);
    }

    public function testSchemasListAndSingle()
    {
        ob_start();
        $this->scim->showSchemas(null);
        $list = ob_get_clean();
        $this->assertStringContainsString('urn:ietf:params:scim:schemas:core:2.0:User', $list);
        $this->assertStringContainsString('urn:ietf:params:scim:schemas:core:2.0:Group', $list);

        ob_start();
        $this->scim->showSchemas('urn:ietf:params:scim:schemas:core:2.0:User');
        $single = ob_get_clean();
        $this->assertStringContainsString('"name":"User"', $single);
        $this->assertStringContainsString('"name":"userName"', $single);
        // password must be advertised as write-only / never returned.
        $this->assertStringContainsString('"mutability":"writeOnly"', $single);
    }
}