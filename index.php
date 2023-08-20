<?php

session_start();

require 'vendor/autoload.php';

use \VoltCMS\UserAccess\User;
use \VoltCMS\UserAccess\FileUserProvider;
use \VoltCMS\UserAccess\FileGroupProvider;
use VoltCMS\UserAccess\SCIMApp;

$userProvider = new FileUserProvider('testdata/user');
$groupProvider = new FileGroupProvider('testdata/group');

if ($userProvider->isNameExisting('Administrator')){
    $admin = new User('Administrator', 'Administrator', 'Administrator User', 'administrator@useraccess.net', true, User::hashPassword('abcd1234'), array('Everyone', 'Administrators'));
    $userProvider->create($admin);
}

$app = new SCIMApp($userProvider, $groupProvider);