<?php

use PHPUnit\Framework\TestCase;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\Passkey;
use VoltCMS\UserAccess\PasskeyProvider;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;
use VoltCMS\UserAccess\Utils;

class PasskeyProviderTest extends TestCase
{
    private UserProvider $userProvider;
    private PasskeyProvider $passkeyProvider;

    protected function setUp(): void
    {
        $this->userProvider = UserProvider::getInstance(['directory' => 'tests/data/users']);
        GroupProvider::getInstance(['directory' => 'tests/data/groups']);
        $this->passkeyProvider = PasskeyProvider::getInstance(['directory' => 'tests/data/passkeys']);
        $this->userProvider->deleteAll();
        $this->passkeyProvider->deleteAll();
    }

    protected function tearDown(): void
    {
        $this->passkeyProvider->deleteAll();
        $this->userProvider->deleteAll();
    }

    private function makePasskey(string $userId, string $credentialId): Passkey
    {
        $passkey = new Passkey();
        $passkey->setUserId($userId);
        $passkey->setCredentialId($credentialId);
        $passkey->setPublicKey(Utils::base64UrlEncode('cose-key-bytes'));
        return $passkey;
    }

    public function testCreatedPasskeyCanBeFoundByCredentialId(): void
    {
        $created = $this->passkeyProvider->create($this->makePasskey('11111111-1111-1111-1111-111111111111', 'AbCdEfGh'));

        $this->assertNotSame('', $created->getId());
        $this->assertTrue($this->passkeyProvider->exists('credentialId', 'AbCdEfGh'));
        $this->assertSame($created->getId(), $this->passkeyProvider->read('credentialId', 'AbCdEfGh')->getId());
    }

    public function testCredentialIdLookupIsCaseSensitive(): void
    {
        // FileDB matches case-insensitively; base64url ids differing only in
        // case are different credentials and must not resolve to each other.
        $this->passkeyProvider->create($this->makePasskey('11111111-1111-1111-1111-111111111111', 'AbCdEfGh'));

        $this->assertFalse($this->passkeyProvider->exists('credentialId', 'abcdefgh'));
        $this->passkeyProvider->create($this->makePasskey('11111111-1111-1111-1111-111111111111', 'abcdefgh'));
        $this->assertCount(1, $this->passkeyProvider->find('credentialId', 'abcdefgh'));
        $this->assertCount(2, $this->passkeyProvider->readAll());
    }

    public function testDuplicateCredentialIdIsRejected(): void
    {
        $this->passkeyProvider->create($this->makePasskey('11111111-1111-1111-1111-111111111111', 'AbCdEfGh'));

        $this->expectExceptionMessage('EXCEPTION_PASSKEY_ALREADY_EXIST');
        $this->passkeyProvider->create($this->makePasskey('33333333-3333-3333-3333-333333333333', 'AbCdEfGh'));
    }

    public function testUpdatePersistsTheSignCount(): void
    {
        $passkey = $this->passkeyProvider->create($this->makePasskey('11111111-1111-1111-1111-111111111111', 'AbCdEfGh'));
        $passkey->setSignCount(42);
        $this->passkeyProvider->update($passkey);

        $this->assertSame(42, $this->passkeyProvider->read('id', $passkey->getId())->getSignCount());
    }

    public function testDeletingAUserDeletesTheirPasskeys(): void
    {
        $user = new User();
        $user->setUserName('passkeyowner');
        $user->setPassword('password');
        $user = $this->userProvider->create($user);
        $other = new User();
        $other->setUserName('otherowner');
        $other->setPassword('password');
        $other = $this->userProvider->create($other);

        $this->passkeyProvider->create($this->makePasskey($user->getId(), 'AAAA'));
        $this->passkeyProvider->create($this->makePasskey($user->getId(), 'BBBB'));
        $this->passkeyProvider->create($this->makePasskey($other->getId(), 'CCCC'));

        $this->userProvider->delete($user->getId());

        $this->assertSame([], $this->passkeyProvider->find('userId', $user->getId()));
        $this->assertCount(1, $this->passkeyProvider->find('userId', $other->getId()));
    }

}
