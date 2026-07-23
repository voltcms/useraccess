<?php

require '../../vendor/autoload.php';

use VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SCIM;

$userProvider = UserProvider::getInstance(array('directory' => '../data/users'));
$groupProvider = GroupProvider::getInstance(array('directory' => '../data/groups'));

if (!$userProvider->exists('userName', 'Administrator')){
    $user = new User();
    $user->setUserName('Administrator');
    $user->setDisplayName('Admin Last');
    $user->setFamilyName('Last');
    $user->setGivenName('Admin');
    $user->setEmail('Administrator@voltcms.com');
    $user->setPassword('daze4726DKAU!!!!');
    $user = $userProvider->create($user);
    $group = $groupProvider->read('displayName', 'Administrators');
    $group->addMember($user->getId());
    $groupProvider->update($group);
}

// WARNING: DEMO ONLY. The third argument disables authentication so the
// static demo UI (which has no login flow) can call the SCIM API directly.
// This leaves the entire user/group API open to anonymous callers. NEVER do
// this in production: construct `new SCIM($userProvider, $groupProvider)`
// (authentication enforced by default) and drive it with an admin session
// or HTTP Basic admin credentials.
$app = new SCIM($userProvider, $groupProvider, false);
$app->runRouter();