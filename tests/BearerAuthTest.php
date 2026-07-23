<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\BearerAuth;

class BearerAuthTest extends TestCase
{

    protected function tearDown(): void
    {
        unset($_SERVER['HTTP_AUTHORIZATION'], $_SERVER['REDIRECT_HTTP_AUTHORIZATION']);
    }

    public function testNotConfiguredNeverAuthenticates()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer anything';
        $auth = new BearerAuth();
        $this->assertFalse($auth->isConfigured());
        $this->assertFalse($auth->authenticate());
    }

    public function testValidTokenAuthenticates()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer s3cr3t-token';
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertTrue($auth->isConfigured());
        $this->assertTrue($auth->authenticate());
    }

    public function testWrongTokenDoesNotAuthenticate()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer wrong-token';
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertFalse($auth->authenticate());
    }

    public function testMultipleTokensAnyValidAuthenticates()
    {
        $auth = new BearerAuth(['token-a', 'token-b']);
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer token-b';
        $this->assertTrue($auth->authenticate());
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer token-a';
        $this->assertTrue($auth->authenticate());
    }

    public function testNonBearerSchemeDoesNotAuthenticate()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode('user:pass');
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertFalse($auth->authenticate());
        $this->assertNull(BearerAuth::extractToken());
    }

    public function testMissingHeaderDoesNotAuthenticate()
    {
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertFalse($auth->authenticate());
    }

    public function testEmptyBearerTokenIsIgnored()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer    ';
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertNull(BearerAuth::extractToken());
        $this->assertFalse($auth->authenticate());
    }

    public function testBlankConfiguredTokensAreIgnored()
    {
        // Configuring only blank tokens must not authorize a blank presented one.
        $auth = new BearerAuth(['', '   ']);
        $this->assertFalse($auth->isConfigured());
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ';
        $this->assertFalse($auth->authenticate());
    }

    public function testRedirectAuthorizationFallbackIsHonored()
    {
        // Apache passes the header through as REDIRECT_HTTP_AUTHORIZATION.
        $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] = 'Bearer s3cr3t-token';
        $auth = new BearerAuth(['s3cr3t-token']);
        $this->assertTrue($auth->authenticate());
    }

}
