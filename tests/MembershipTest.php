<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;

class MembershipTest extends TestCase
{

    public function testDeletingUserRemovesGroupMembership()
    {
        $userProvider = UserProvider::getInstance(array('directory' => 'tests/data/users'));
        $groupProvider = GroupProvider::getInstance(array('directory' => 'tests/data/groups'));

        $userProvider->deleteAll();
        $groupProvider->deleteAll();

        $user = new User();
        $user->setUserName('memberuser');
        $user->setDisplayName('Member User');
        $user->setPassword('password');
        $user = $userProvider->create($user);

        $group = new Group();
        $group->setDisplayName('Team');
        $group = $groupProvider->create($group);
        $group->addMember($user->getId());
        $groupProvider->update($group);

        // Also add to the auto-created Administrators group.
        $admins = $groupProvider->read('displayName', 'Administrators');
        $admins->addMember($user->getId());
        $groupProvider->update($admins);

        $group = $groupProvider->read('id', $group->getId());
        $admins = $groupProvider->read('displayName', 'Administrators');
        $this->assertTrue($group->hasMember($user->getId()));
        $this->assertTrue($admins->hasMember($user->getId()));

        // Deleting the user must strip them from every group.
        $userProvider->delete($user->getId());

        $group = $groupProvider->read('id', $group->getId());
        $admins = $groupProvider->read('displayName', 'Administrators');
        $this->assertFalse($group->hasMember($user->getId()));
        $this->assertFalse($admins->hasMember($user->getId()));

        $userProvider->deleteAll();
        $groupProvider->deleteAll();
    }

}
