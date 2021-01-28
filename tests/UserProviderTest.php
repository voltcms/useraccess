<?php

use \PHPUnit\Framework\TestCase;

use \PragmaPHP\UserAccess\FileUserProvider;
use \PragmaPHP\UserAccess\StaticUserProvider;
use \PragmaPHP\UserAccess\User;
use \PragmaPHP\UserAccess\UserProviderInterface;

class UserProviderTest extends TestCase {

    public function test() {
        $this->performTest(new StaticUserProvider());

        $userProvider = new FileUserProvider('testdata/users');
        $userProvider->deleteUsers();
        $this->performTest(new FileUserProvider('testdata/users'));
    }

    public function performTest(UserProviderInterface $provider) {
        if ($provider->isUserNameExisting('userid1')) {
            $provider->deleteUser('userid1');
        }
        if ($provider->isUserNameExisting('USERID_2')) {
            $provider->deleteUser('USERID_2');
        }
        $this->assertFalse($provider->isUserNameExisting('userid1'));
        $this->assertFalse($provider->isUserNameExisting('USERID_2'));

        $user1 = new User('userid1', 'userid1', 'userid1 test', 'userid1.test@test.com', true, User::hashPassword('password1'), array('Everyone', 'Administrators'));
        $user2 = new User('USERID_2', 'USERID_2', 'USERID_2 test', 'userid_2.test@test.com', true, User::hashPassword('password2'), array('Everyone', 'Administrators'));
        $user3 = new User('user', 'user', 'user test', 'user.test@test.com', true, User::hashPassword('password1'), array('Everyone', 'Administrators'));

        $user1 = $provider->createUser($user1);
        $user2 = $provider->createUser($user2);
        $user3 = $provider->createUser($user3);

        $this->assertTrue($provider->isUserNameExisting('userid1'));
        $this->assertTrue($provider->isUserNameExisting('USERID_2'));
        $user_test1 = $provider->getUser($user1->id);
        $user_test2 = $provider->getUser($user2->id);
        $this->assertNotEmpty($user_test1);
        $this->assertNotEmpty($user_test2);

        $this->assertEquals('userid1', $user_test1->userName);
        $this->assertEquals('userid1.test@test.com', $user_test1->email);
        // $this->assertEquals(['userid1.test@test.com'], $user_test1->getEmails());
        $this->assertTrue($user_test1->groups == ['Everyone', 'Administrators']);
        $this->assertFalse($user_test1->groups == ['Guests']);
        $this->assertEquals('userid_2', $user_test2->userName);
        $this->assertEquals('userid_2.test@test.com', $user_test2->email);
        // $this->assertEquals(['userid_2.test@test.com'], $user_test2->getEmails());
        $this->assertTrue($user_test2->groups == ['Everyone', 'Administrators']);
        $this->assertFalse($user_test2->groups == ['Guests']);
        $this->assertTrue($user_test1->verifyPassword('password1'));
        $this->assertTrue($user_test2->verifyPassword('password2'));

        $find = $provider->findUsers('displayName', 'userid1 TEST ');
        $this->assertNotEmpty($find);
        $this->assertEquals(1, count($find));
        $find = $provider->findUsers('email', 'userid1.test@test.com');
        $this->assertNotEmpty($find);
        $this->assertEquals(1, count($find));
        $find = $provider->findUsers('displayName', '*USERID*');
        $this->assertNotEmpty($find);
        $this->assertEquals(2, count($find));

        $this->assertFalse($provider->isUserNameExisting('userid3'));
        try {
            $provider->getUser('userid3');
        } catch (\Exception $e) {
            $this->assertNotEmpty($e);
        }

        $user_test1 = $provider->getUser($user1->id);
        $user_test1->displayName = 'userid1 test update';
        $user_test1->passwordHash = User::hashPassword('password1_update');
        $user_test1->email = 'userid1.test_update@test.com';
        $user_test1->groups = ['Administrators'];
        $provider->updateUser($user_test1);
        $user_test1 = $provider->getUser($user1->id);
        $this->assertEquals('userid1', $user_test1->userName);
        $this->assertEquals('userid1.test_update@test.com', $user_test1->email);
        $this->assertFalse($user_test1->verifyPassword('password1'));
        $this->assertTrue($user_test1->verifyPassword('password1_update'));
        $this->assertTrue($user_test1->groups == ['Administrators']);

        // delete attribute test
        $user_test1->displayName = '';
        $provider->updateUser($user_test1);
        $user_test1 = $provider->getUser($user_test1->id);
        $this->assertEquals('', $user_test1->displayName);
        $user_test1->displayName = 'userid1 test';
        $provider->updateUser($user_test1);
        $user_test1 = $provider->getUser($user_test1->id);
        $this->assertEquals('userid1 test', $user_test1->displayName);
        $provider->updateUser($user_test1);

        $users = $provider->getUsers();
        $this->assertNotEmpty($users);
        $this->assertEquals(3, count($users));

        $provider->deleteUsers();

    }

}