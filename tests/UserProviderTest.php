<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SessionAuth;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProviderInterface;

class UserProviderTest extends TestCase
{

    public function test()
    {
        $provider = UserProvider::getInstance(array('directory' => 'testdata/users'));
        $groupProvider = GroupProvider::getInstance(array('directory' => 'testdata/groups'));
        $everyoneGroup = new Group();
        $everyoneGroup->setDisplayName('Everyone');
        $everyoneGroup = $groupProvider->create($everyoneGroup);
        $administratorsGroup = new Group();
        $administratorsGroup->setDisplayName('Administrators');
        $administratorsGroup = $groupProvider->create($administratorsGroup);
        $this->assertTrue($groupProvider->exists('displayName', 'Everyone'));
        $this->assertTrue($groupProvider->exists('displayName', 'Administrators'));

        if ($provider->exists('userName', 'userid1')) {
            $user = $provider->read('userName', 'userid1');
            $provider->delete($user->getId());
        }
        if ($provider->exists('userName', 'USERID_2')) {
            $user = $provider->read('userName', 'USERID_2');
            $provider->delete($user->getId());
        }
        $this->assertFalse($provider->exists('userName', 'userid1'));
        $this->assertFalse($provider->exists('userName', 'USERID_2'));

        $user1 = new User();
        $user1->setUserName('userid1');
        $user1->setDisplayName('userid1 test');
        $user1->setEmail('userid1.test@test.com');
        $user1->setPassword('password1');
        $user1 = $provider->create($user1);

        $administratorsGroup->addMember($user1->getId());
        $everyoneGroup->addMember($user1->getId());
        $groupProvider->update($administratorsGroup);
        $groupProvider->update($everyoneGroup);
        $user2 = new User();
        $user2->setUserName('USERID_2');
        $user2->setDisplayName('USERID_2 test');
        $user2->setEmail('userid_2.test@test.com');
        $user2->setPassword('password2');
        $user2 = $provider->create($user2);

        $administratorsGroup->addMember($user2->getId());
        $everyoneGroup->addMember($user2->getId());
        $groupProvider->update($administratorsGroup);
        $groupProvider->update($everyoneGroup);
        $user3 = new User();
        $user3->setUserName('user');
        $user3->setDisplayName('user test');
        $user3->setEmail('user.test@test.com');
        $user3->setPassword('password1');
        $user3 = $provider->create($user3);

        $administratorsGroup->addMember($user3->getId());
        $everyoneGroup->addMember($user3->getId());
        $groupProvider->update($administratorsGroup);
        $groupProvider->update($everyoneGroup);


        $this->assertTrue($provider->exists('userName', 'userid1'));
        $this->assertTrue($provider->exists('userName', 'USERID_2'));
        $user_test1 = $provider->read('id', $user1->getId());
        $user_test2 = $provider->read('id', $user2->getId());
        $this->assertNotEmpty($user_test1);
        $this->assertNotEmpty($user_test2);

        $this->assertEquals('userid1', $user_test1->getUserName());
        $this->assertEquals('userid1.test@test.com', $user_test1->getEmail());
        // $this->assertEquals(['userid1.test@test.com'], $user_test1->getEmails());
        $this->assertTrue($user_test1->isMemberOf('everyone'));
        $this->assertTrue($user_test1->isMemberOf('administrators'));
        $this->assertFalse($user_test1->isMemberOf('Guests'));
        $this->assertEquals('USERID_2', $user_test2->getUserName());
        $this->assertEquals('userid_2.test@test.com', $user_test2->getEmail());
        // $this->assertEquals(['userid_2.test@test.com'], $user_test2->getEmails());
        $this->assertTrue($user_test2->isMemberOf('everyone'));
        $this->assertTrue($user_test2->isMemberOf('administrators'));
        $this->assertFalse($user_test2->isMemberOf('Guests'));
        $this->assertTrue($user_test1->verifyPassword('password1'));
        $this->assertTrue($user_test2->verifyPassword('password2'));

        $find = $provider->find('displayName', 'userid1 TEST ');
        $this->assertNotEmpty($find);
        $this->assertEquals(1, count($find));
        $find = $provider->find('email', 'userid1.test@test.com');
        $this->assertNotEmpty($find);
        $this->assertEquals(1, count($find));
        $find = $provider->find('email', 'userid_2.test@test.com');
        $this->assertNotEmpty($find);
        $this->assertEquals(1, count($find));
        $this->assertEquals('USERID_2', $find[0]->getUserName());
        $find = $provider->find('displayName', '*USERID*');
        $this->assertNotEmpty($find);
        $this->assertEquals(2, count($find));

        $this->assertFalse($provider->exists('userName', 'userid3'));
        try {
            $provider->read('userName', 'userid3');
        } catch (Exception $e) {
            $this->assertNotEmpty($e);
        }

        $user_test1 = $provider->read('id', $user1->getId());
        $user_test1->setDisplayName('userid1 test update');
        $user_test1->setPasswordHash(User::hashPassword('password1_update'));
        $user_test1->setEmail('userid1.test_update@test.com');
        $user_test1 = $provider->update($user_test1);

        $administratorsGroup = $groupProvider->read('displayName', 'Administrators');
        $administratorsGroup->addMember($user_test1->getId());
        $user_test1 = $provider->read('id', $user_test1->getId());
        $this->assertEquals('userid1', $user_test1->getUserName());
        $this->assertEquals('userid1.test_update@test.com', $user_test1->getEmail());
        $this->assertFalse($user_test1->verifyPassword('password1'));
        $this->assertTrue($user_test1->verifyPassword('password1_update'));
        $this->assertTrue($user_test1->isMemberOf('administrators'));

        // delete attribute test
        $user_test1->setDisplayName('');
        $provider->update($user_test1);
        $user_test1 = $provider->read('id', $user_test1->getId());
        $this->assertEquals('', $user_test1->getDisplayName());
        $user_test1->setDisplayName('userid1 test');
        $provider->update($user_test1);
        $user_test1 = $provider->read('id', $user_test1->getId());
        $this->assertEquals('userid1 test', $user_test1->getDisplayName());
        $provider->update($user_test1);

        $users = $provider->readAll();
        $this->assertNotEmpty($users);
        $this->assertEquals(3, count($users));

        // $_SERVER[SessionAuth::HTTP_X_CSRF_TOKEN] = 'fetch';
        $sessionAuth = SessionAuth::getInstance($provider);
        $this->assertNotEmpty($_SESSION[SessionAuth::UA_CSRF]);
        $this->assertFalse($sessionAuth->login('userid1', 'password1_xxx'));
        $this->assertFalse($sessionAuth->login('xxxxx', 'password1_xxx'));
        $this->assertFalse($sessionAuth->login('userid1.xxx@test.com', 'password1_update'));
        $this->assertFalse($sessionAuth->isLoggedIn());
        $this->assertEquals($_SESSION[SessionAuth::UA_ATTEMPTS], 3);
        $this->assertFalse($_SESSION[SessionAuth::UA_AUTH]);
        $this->assertEquals($_SESSION[SessionAuth::UA_USERNAME], '');
        $this->assertTrue($_SESSION[SessionAuth::UA_GROUPS] == []);
        $this->assertTrue($sessionAuth->login('userid1', 'password1_update', $_SESSION[SessionAuth::UA_CSRF]));
        $this->assertTrue($sessionAuth->isLoggedIn());
        $this->assertEquals($_SESSION[SessionAuth::UA_ATTEMPTS], 0);
        $this->assertTrue($_SESSION[SessionAuth::UA_AUTH]);
        $this->assertEquals($_SESSION[SessionAuth::UA_USERNAME], 'userid1');
        $this->assertEquals($_SESSION[SessionAuth::UA_DISPLAYNAME], 'userid1 test');
        $this->assertEquals($_SESSION[SessionAuth::UA_EMAIL], 'userid1.test_update@test.com');
        $this->assertNotEmpty($sessionAuth->getLoginInfo());
        $sessionAuth->logOut();
        $this->assertFalse($_SESSION[SessionAuth::UA_AUTH]);
        $this->assertEquals($_SESSION[SessionAuth::UA_USERNAME], '');
        $this->assertTrue($_SESSION[SessionAuth::UA_GROUPS] == []);
        $this->assertNotEmpty($sessionAuth->getLoginInfo());

        $this->assertTrue($sessionAuth->login('userid1.TEST_UPDATE@test.com', 'password1_update', $_SESSION[SessionAuth::UA_CSRF]));
        $this->assertTrue($sessionAuth->isLoggedIn());
        $this->assertEquals($_SESSION[SessionAuth::UA_ATTEMPTS], 0);
        $this->assertTrue($_SESSION[SessionAuth::UA_AUTH]);
        $this->assertEquals($_SESSION[SessionAuth::UA_USERNAME], 'userid1');
        $this->assertEquals($_SESSION[SessionAuth::UA_DISPLAYNAME], 'userid1 test');
        $this->assertEquals($_SESSION[SessionAuth::UA_EMAIL], 'userid1.test_update@test.com');
        $this->assertNotEmpty($sessionAuth->getLoginInfo());

        // $this->assertFalse($user_test1->verifyPassword('password1'));
        // $this->assertTrue($user_test1->verifyPassword('password1_update'));
        // $this->assertTrue($user_test1->getGroups() == ['Administrators']);

        $provider->deleteAll();
        $groupProvider->deleteAll();
    }

}
