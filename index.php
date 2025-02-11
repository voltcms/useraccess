<?php

require 'vendor/autoload.php';

use VoltCMS\UserAccess\Group;
use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProvider;
use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SCIM;

$userProvider = UserProvider::getInstance(array('directory' => 'testdata/users'));
$groupProvider = GroupProvider::getInstance(array('directory' => 'testdata/groups'));

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

$app = new SCIM($userProvider, $groupProvider, false);
$app->runRouter();