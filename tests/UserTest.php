<?php

use \PHPUnit\Framework\TestCase;

use \PragmaPHP\UserAccess\User;

class UserTest extends TestCase {

    public function test() {
        $user = new User(null, 'userid1', 'user id 1', 'userid1@test.com', true, User::hashPassword('password'), []);
        $this->assertNotEmpty($user);
        $this->assertEquals('userid1', $user->userName);
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