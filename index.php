<?php

session_start();

require 'vendor/autoload.php';

use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\UserProvider;
//use \VoltCMS\UserAccess\GroupProvider;
use \VoltCMS\UserAccess\SCIMApp;

$userProvider = UserProvider::getInstance(array('directory' => 'testdata/users'));
//$groupProvider = FileGroupProvider::getInstance(array('directory' => 'testdata/groups'));

if (!$userProvider->exists('userName', 'Administrator')){
    $user1 = new User();
    $user1->setUserName('Administrator');
    $user1->setDisplayName('Admin Last');
    $user1->setFamilyName('Last');
    $user1->setGivenName('Admin');
    $user1->setEmail('Administrator@voltcms.com');
    $user1->setPassword('daze4726DKAU!!!!');
    $user1->setGroups(array('Everyone', 'Administrators'));
    $user1 = $userProvider->create($user1);
}

// if (!$userProvider->isNameExisting('Administrator')){
//     echo("admin is not existing");
// } else {
//     echo("admin is existing");
// }

$app = new SCIMApp($userProvider);