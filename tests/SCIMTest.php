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
    private $serverBackup;

    protected function setUp(): void
    {
        $this->userProviderMock = $this->createMock(UserProviderInterface::class);
        $this->groupProviderMock = $this->createMock(GroupProviderInterface::class);

        // Location URLs in real (unmocked) entities are derived from the request.
        $this->serverBackup = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'example.test';
        $_SERVER['SCRIPT_NAME'] = '/api/index.php';

        $this->scim = new SCIM($this->userProviderMock, $this->groupProviderMock);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
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

    public function testCreateUserStoresCustomAttributes()
    {
        $this->userProviderMock->method('exists')->willReturn(false);
        $this->userProviderMock
            ->expects($this->once())
            ->method('create')
            ->willReturnCallback(function (User $user) {
                // Stand in for the provider handing back the stored document.
                $user->setAttributes([
                    '_id' => '77777777-7777-7777-7777-777777777777',
                    '_created' => 1700000000,
                    '_modified' => 1700000000,
                ]);
                return $user;
            });

        $body = json_encode([
            'schemas' => [User::SCHEMA, User::CUSTOM_SCHEMA],
            'userName' => 'customuser',
            'password' => 'password',
            User::CUSTOM_SCHEMA => ['department' => 'Engineering', 'employeeNumber' => 4711],
        ]);

        ob_start();
        $this->scim->createUser($body);
        $out = ob_get_clean();

        $this->assertStringContainsString('"' . User::CUSTOM_SCHEMA . '":{"department":"Engineering","employeeNumber":4711}', $out);
        $this->assertStringContainsString(User::CUSTOM_SCHEMA, $out);
        $this->assertStringNotContainsString('customAttributes', $out);
    }

    public function testCreateUserAcceptsTheExtensionWithoutDeclaringItInSchemas()
    {
        $this->userProviderMock->method('exists')->willReturn(false);
        $this->userProviderMock
            ->expects($this->once())
            ->method('create')
            ->willReturnCallback(function (User $user) {
                $user->setAttributes(['_id' => 'id', '_created' => 1700000000, '_modified' => 1700000000]);
                return $user;
            });

        $body = json_encode([
            'schemas' => [User::SCHEMA],
            'userName' => 'lenientuser',
            'password' => 'password',
            User::CUSTOM_SCHEMA => ['tenant' => 'acme'],
        ]);

        ob_start();
        $this->scim->createUser($body);
        $out = ob_get_clean();

        $this->assertStringContainsString('"tenant":"acme"', $out);
    }

    public function testPutUserPassesTheCustomExtensionToTheEntity()
    {
        $userID = '88888888-8888-8888-8888-888888888888';
        $user = $this->createMock(User::class);
        $user->method('getId')->willReturn($userID);
        $user->method('toSCIM')->willReturn(['id' => $userID]);
        $user->expects($this->once())
            ->method('fromSCIM')
            ->with($this->callback(function (array $attributes) {
                return ($attributes[User::CUSTOM_SCHEMA] ?? null) === ['department' => 'Support'];
            }));

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => [User::SCHEMA, User::CUSTOM_SCHEMA],
            'userName' => 'customuser',
            User::CUSTOM_SCHEMA => ['department' => 'Support'],
        ]);

        $this->expectOutputRegex('/"id":"88888888-8888-8888-8888-888888888888"/');
        $this->scim->putUser($body, $userID);
    }

    public function testPutUserWithAnEmptyExtensionClearsCustomAttributes()
    {
        $userID = '18181818-1818-1818-1818-181818181818';
        $user = $this->createMock(User::class);
        $user->method('getId')->willReturn($userID);
        $user->method('toSCIM')->willReturn(['id' => $userID]);
        // An empty extension object is a body, not a malformed request: it is
        // how a client drops every custom attribute.
        $user->expects($this->once())
            ->method('fromSCIM')
            ->with($this->callback(function (array $attributes) {
                return ($attributes[User::CUSTOM_SCHEMA] ?? null) === [];
            }));

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => [User::SCHEMA, User::CUSTOM_SCHEMA],
            'userName' => 'customuser',
            User::CUSTOM_SCHEMA => new stdClass(),
        ]);

        $this->expectOutputRegex('/"id":"18181818-1818-1818-1818-181818181818"/');
        $this->scim->putUser($body, $userID);
    }

    public function testPatchUserSetsASingleCustomAttribute()
    {
        $userID = '99999999-9999-9999-9999-999999999999';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setCustomAttribute')->with('department', 'Engineering');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'path' => User::CUSTOM_SCHEMA . ':department', 'value' => 'Engineering'],
            ],
        ]);

        $this->expectOutputRegex('/"id":"99999999-9999-9999-9999-999999999999"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserSetsACustomAttributeViaTheStorageAliasPath()
    {
        $userID = '10101010-1010-1010-1010-101010101010';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setCustomAttribute')->with('tenant', 'acme');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'add', 'path' => 'customAttributes.tenant', 'value' => 'acme'],
            ],
        ]);

        $this->expectOutputRegex('/"id":"10101010-1010-1010-1010-101010101010"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserReplaceOnTheExtensionRootSwapsTheWholeSet()
    {
        $userID = '12121212-1212-1212-1212-121212121212';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setCustomAttributes')->with(['tenant' => 'acme']);
        $user->expects($this->never())->method('setCustomAttribute');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'path' => User::CUSTOM_SCHEMA, 'value' => ['tenant' => 'acme']],
            ],
        ]);

        $this->expectOutputRegex('/"id":"12121212-1212-1212-1212-121212121212"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserAddOnTheExtensionRootMergesAttributes()
    {
        $userID = '13131313-1313-1313-1313-131313131313';
        $user = $this->createMock(User::class);
        // 'add' must merge, so each attribute is set individually and the
        // existing set is left in place.
        $matcher = $this->exactly(2);
        $user->expects($matcher)->method('setCustomAttribute');
        $user->expects($this->never())->method('setCustomAttributes');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'add', 'path' => User::CUSTOM_SCHEMA, 'value' => ['tenant' => 'acme', 'department' => 'Engineering']],
            ],
        ]);

        $this->expectOutputRegex('/"id":"13131313-1313-1313-1313-131313131313"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserRemovesASingleCustomAttribute()
    {
        $userID = '14141414-1414-1414-1414-141414141414';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('removeCustomAttribute')->with('department');
        $user->expects($this->never())->method('clearCustomAttributes');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'remove', 'path' => User::CUSTOM_SCHEMA . ':department'],
            ],
        ]);

        $this->expectOutputRegex('/"id":"14141414-1414-1414-1414-141414141414"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPatchUserRemovesEveryCustomAttribute()
    {
        $userID = '15151515-1515-1515-1515-151515151515';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('clearCustomAttributes');
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'remove', 'path' => User::CUSTOM_SCHEMA],
            ],
        ]);

        $this->expectOutputRegex('/"id":"15151515-1515-1515-1515-151515151515"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testPathlessPatchCarriesTheCustomExtension()
    {
        $userID = '16161616-1616-1616-1616-161616161616';
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('setDisplayName')->with('Custom User');
        $user->expects($this->once())->method('setCustomAttributes')->with(['tenant' => 'acme']);
        $user->method('toSCIM')->willReturn(['id' => $userID]);

        $this->userProviderMock->method('exists')->willReturn(true);
        $this->userProviderMock->method('read')->willReturn($user);
        $this->userProviderMock->expects($this->once())->method('update')->willReturn($user);

        $body = json_encode([
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [
                ['op' => 'replace', 'value' => [
                    'displayName' => 'Custom User',
                    User::CUSTOM_SCHEMA => ['tenant' => 'acme'],
                ]],
            ],
        ]);

        $this->expectOutputRegex('/"id":"16161616-1616-1616-1616-161616161616"/');
        $this->scim->patchUser($body, $userID);
    }

    public function testDiscoveryAdvertisesTheCustomAttributeExtension()
    {
        ob_start();
        $this->scim->showResourceTypes('User');
        $resourceType = ob_get_clean();
        $this->assertStringContainsString('"schemaExtensions":[{"schema":"' . User::CUSTOM_SCHEMA . '","required":false}]', $resourceType);

        ob_start();
        $this->scim->showSchemas(null);
        $list = ob_get_clean();
        $this->assertStringContainsString(User::CUSTOM_SCHEMA, $list);

        ob_start();
        $this->scim->showSchemas(User::CUSTOM_SCHEMA);
        $single = ob_get_clean();
        $this->assertStringContainsString('"name":"CustomUserAttributes"', $single);
    }
}