<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\HeaderAuth;
use \VoltCMS\UserAccess\UserProviderInterface;
use \VoltCMS\UserAccess\User;

class HeaderAuthTest extends TestCase
{

    protected function tearDown(): void
    {
        unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
    }

    private function setBasicHeader(string $raw): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode($raw);
    }

    public function testValidCredentialsReturnUser()
    {
        $this->setBasicHeader('alice:secret');

        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('verifyPassword')->with('secret')->willReturn(true);

        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('exists')->willReturn(true);
        $provider->method('read')->willReturn($user);

        $this->assertSame($user, HeaderAuth::checkBasicAuthentication($provider));
    }

    public function testPasswordContainingColonIsPreserved()
    {
        $this->setBasicHeader('alice:sec:ret');

        $user = $this->createMock(User::class);
        // The password after the first colon must be kept intact.
        $user->expects($this->once())->method('verifyPassword')->with('sec:ret')->willReturn(true);

        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('exists')->willReturn(true);
        $provider->method('read')->willReturn($user);

        $this->assertSame($user, HeaderAuth::checkBasicAuthentication($provider));
    }

    public function testWrongPasswordReturnsNull()
    {
        $this->setBasicHeader('alice:wrong');

        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('verifyPassword')->willReturn(false);

        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('exists')->willReturn(true);
        $provider->method('read')->willReturn($user);

        $this->assertNull(HeaderAuth::checkBasicAuthentication($provider));
    }

    public function testMalformedHeaderWithoutColonReturnsNullAndDoesNotQueryProvider()
    {
        $this->setBasicHeader('no-colon-here');

        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects($this->never())->method('exists');
        $provider->expects($this->never())->method('read');

        $this->assertNull(HeaderAuth::checkBasicAuthentication($provider));
    }

    public function testNonBasicSchemeReturnsNull()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer sometoken';

        $provider = $this->createMock(UserProviderInterface::class);
        $provider->expects($this->never())->method('exists');
        $provider->expects($this->never())->method('read');

        $this->assertNull(HeaderAuth::checkBasicAuthentication($provider));
    }

    public function testUnknownUserReturnsNull()
    {
        $this->setBasicHeader('ghost:secret');

        $provider = $this->createMock(UserProviderInterface::class);
        $provider->method('exists')->willReturn(false);
        $provider->expects($this->never())->method('read');

        $this->assertNull(HeaderAuth::checkBasicAuthentication($provider));
    }

}
