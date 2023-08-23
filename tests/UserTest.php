<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\User;

class UserTest extends TestCase
{

    public function test()
    {
        $user = new User();
        $user->setUserName('userid1');
        $user->setDisplayName('user id 1');
        $user->setEmail('userid1@test.com');
        $user->setPassword('password');
        $this->assertNotEmpty($user);
        $this->assertEquals('userid1', $user->getUserName());
        $userAttributes = $user->getAttributes();
        $this->assertEquals('userid1', $userAttributes['userName']);
        $this->assertTrue($user->verifyPassword('password'));
        $user->setPassword('password2');
        $this->assertTrue($user->verifyPassword('password2'));
        $this->assertFalse($user->verifyPassword('wrong_password'));
        // echo $user->toJson();
        // print_r($user->getAttributes());
    }

}
