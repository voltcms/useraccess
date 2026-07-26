<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;

class CustomAttributesTest extends TestCase
{
    private $serverBackup;

    protected function setUp(): void
    {
        // toSCIM() derives the location URL from the request context, so give it
        // one; without it the entity cannot be serialized in a unit context.
        $this->serverBackup = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'example.test';
        $_SERVER['SCRIPT_NAME'] = '/api/index.php';
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
    }

    // Builds a user that can be serialized: toSCIM() formats the FileDB
    // timestamps, which are empty strings on a brand-new entity.
    private function makeUser(): User
    {
        $user = new User();
        $user->setAttributes([
            '_id' => '11111111-1111-1111-1111-111111111111',
            '_created' => 1700000000,
            '_modified' => 1700000000,
        ]);
        $user->setUserName('customuser');
        return $user;
    }

    public function testSetAndGetCustomAttribute()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $user->setCustomAttribute('employeeNumber', 4711);
        $user->setCustomAttribute('contractor', false);
        $user->setCustomAttribute('costCenters', ['de-01', 'de-02']);
        $user->setCustomAttribute('manager', null);

        $this->assertSame('Engineering', $user->getCustomAttribute('department'));
        $this->assertSame(4711, $user->getCustomAttribute('employeeNumber'));
        $this->assertFalse($user->getCustomAttribute('contractor'));
        $this->assertSame(['de-01', 'de-02'], $user->getCustomAttribute('costCenters'));
        $this->assertNull($user->getCustomAttribute('manager'));
        $this->assertTrue($user->hasCustomAttribute('manager'));
        $this->assertCount(5, $user->getCustomAttributes());
    }

    public function testGetCustomAttributeReturnsDefaultWhenUnset()
    {
        $user = $this->makeUser();

        $this->assertNull($user->getCustomAttribute('missing'));
        $this->assertSame('fallback', $user->getCustomAttribute('missing', 'fallback'));
        $this->assertFalse($user->hasCustomAttribute('missing'));
    }

    public function testCustomAttributeNamesAreCaseInsensitive()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('Department', 'Engineering');

        $this->assertTrue($user->hasCustomAttribute('department'));
        $this->assertSame('Engineering', $user->getCustomAttribute('DEPARTMENT'));

        // Writing the same name in a different casing updates the one attribute
        // rather than creating a second spelling of it.
        $user->setCustomAttribute('deparTMENT', 'Support');
        $this->assertCount(1, $user->getCustomAttributes());
        $this->assertSame('Support', $user->getCustomAttribute('Department'));

        $user->removeCustomAttribute('DEPARTMENT');
        $this->assertFalse($user->hasCustomAttribute('department'));
    }

    public function testSetCustomAttributesReplacesTheWholeSet()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $user->setCustomAttributes(['tenant' => 'acme']);

        $this->assertSame(['tenant' => 'acme'], $user->getCustomAttributes());
    }

    public function testClearCustomAttributes()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $user->clearCustomAttributes();

        $this->assertSame([], $user->getCustomAttributes());
    }

    public function testInvalidCustomAttributeNameIsRejected()
    {
        $user = $this->makeUser();
        foreach (['', '1department', 'depart ment', 'depart.ment', 'dept$', str_repeat('a', 65)] as $name) {
            try {
                $user->setCustomAttribute($name, 'value');
                $this->fail("Expected '" . $name . "' to be rejected as a custom attribute name.");
            } catch (Exception $e) {
                $this->assertSame('EXCEPTION_INVALID_ATTRIBUTE_NAME', $e->getMessage());
            }
        }
        $this->assertSame([], $user->getCustomAttributes());
    }

    public function testCustomAttributeNameAtTheLengthLimitIsAccepted()
    {
        $user = $this->makeUser();
        $name = str_repeat('a', 64);
        $user->setCustomAttribute($name, 'value');

        $this->assertSame('value', $user->getCustomAttribute($name));
    }

    public function testReservedCustomAttributeNameIsRejected()
    {
        $user = $this->makeUser();
        foreach (['passwordHash', 'userName', 'PASSWORD', 'active', 'customAttributes'] as $name) {
            try {
                $user->setCustomAttribute($name, 'value');
                $this->fail("Expected '" . $name . "' to be rejected as a reserved name.");
            } catch (Exception $e) {
                $this->assertSame('EXCEPTION_RESERVED_ATTRIBUTE_NAME', $e->getMessage());
            }
        }
    }

    public function testReservedNameCannotOverwriteCoreStateThroughSetAttributes()
    {
        $user = $this->makeUser();
        $user->setPassword('password');
        $hash = $user->getAttributes()['passwordHash'];

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('EXCEPTION_RESERVED_ATTRIBUTE_NAME');
        try {
            $user->setCustomAttributes(['passwordHash' => 'not-a-hash']);
        } finally {
            $this->assertSame($hash, $user->getAttributes()['passwordHash']);
            $this->assertTrue($user->verifyPassword('password'));
        }
    }

    public function testInvalidCustomAttributeValueIsRejected()
    {
        $user = $this->makeUser();
        $values = [
            'nested object' => ['street' => 'Main'],
            'nested list' => [['a']],
            'object instance' => new stdClass(),
        ];
        foreach ($values as $label => $value) {
            try {
                $user->setCustomAttribute('address', $value);
                $this->fail('Expected a ' . $label . ' to be rejected as a custom attribute value.');
            } catch (Exception $e) {
                $this->assertSame('EXCEPTION_INVALID_ATTRIBUTE_VALUE', $e->getMessage());
            }
        }
    }

    public function testCustomAttributesSurviveTheAttributeRoundTrip()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $attributes = $user->getAttributes();

        $this->assertSame(['department' => 'Engineering'], $attributes['customAttributes']);

        $restored = new User();
        $restored->setAttributes($attributes);
        $this->assertSame('Engineering', $restored->getCustomAttribute('department'));
    }

    public function testToSCIMExposesCustomAttributesUnderTheExtensionSchema()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $payload = $user->toSCIM();

        $this->assertSame(['department' => 'Engineering'], $payload[User::CUSTOM_SCHEMA]);
        $this->assertContains(User::CUSTOM_SCHEMA, $payload['schemas']);
        $this->assertContains(User::SCHEMA, $payload['schemas']);
        // The storage-shaped key must never leak into a SCIM response.
        $this->assertArrayNotHasKey('customAttributes', $payload);
    }

    public function testToSCIMOmitsTheExtensionWhenThereAreNoCustomAttributes()
    {
        $payload = $this->makeUser()->toSCIM();

        $this->assertSame([User::SCHEMA], $payload['schemas']);
        $this->assertArrayNotHasKey(User::CUSTOM_SCHEMA, $payload);
    }

    public function testFromSCIMReadsTheExtensionSchema()
    {
        $user = $this->makeUser();
        $user->fromSCIM([
            'schemas' => [User::SCHEMA, User::CUSTOM_SCHEMA],
            'userName' => 'customuser',
            User::CUSTOM_SCHEMA => ['department' => 'Engineering', 'employeeNumber' => 4711],
        ]);

        $this->assertSame('Engineering', $user->getCustomAttribute('department'));
        $this->assertSame(4711, $user->getCustomAttribute('employeeNumber'));
    }

    public function testFromSCIMWithoutTheExtensionPreservesStoredCustomAttributes()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        // A replace that says nothing about the extension must not wipe it —
        // same rule the entity applies to an omitted 'active'.
        $user->fromSCIM(['schemas' => [User::SCHEMA], 'userName' => 'customuser', 'displayName' => 'Custom User']);

        $this->assertSame('Custom User', $user->getDisplayName());
        $this->assertSame('Engineering', $user->getCustomAttribute('department'));
    }

    public function testFromSCIMWithAnEmptyExtensionClearsCustomAttributes()
    {
        $user = $this->makeUser();
        $user->setCustomAttribute('department', 'Engineering');
        $user->fromSCIM([
            'schemas' => [User::SCHEMA, User::CUSTOM_SCHEMA],
            'userName' => 'customuser',
            User::CUSTOM_SCHEMA => [],
        ]);

        $this->assertSame([], $user->getCustomAttributes());
    }

    public function testCustomAttributesArePersistedByTheProvider()
    {
        $userProvider = UserProvider::getInstance(['directory' => 'tests/data/users']);
        $userProvider->deleteAll();

        $user = new User();
        $user->setUserName('storeduser');
        $user->setPassword('password');
        $user->setCustomAttribute('department', 'Engineering');
        $user->setCustomAttribute('costCenters', ['de-01', 'de-02']);
        $user = $userProvider->create($user);

        $stored = $userProvider->read('id', $user->getId());
        $this->assertSame('Engineering', $stored->getCustomAttribute('department'));
        $this->assertSame(['de-01', 'de-02'], $stored->getCustomAttribute('costCenters'));

        $stored->setCustomAttribute('department', 'Support');
        $stored->removeCustomAttribute('costCenters');
        $userProvider->update($stored);

        $reread = $userProvider->read('userName', 'storeduser');
        $this->assertSame(['department' => 'Support'], $reread->getCustomAttributes());

        $userProvider->deleteAll();
    }

}
