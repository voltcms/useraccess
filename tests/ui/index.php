<?php

session_start();

require '../../vendor/autoload.php';

use \PragmaPHP\UserAccess\User;
use \PragmaPHP\UserAccess\FileUserProvider;
use \PragmaPHP\UserAccess\RestApp;

$userProvider = new FileUserProvider('../../testdata/user');

if ($userProvider->isUserNameExisting('Administrator')){
    $admin = new User('Administrator', 'Administrator', 'Administrator User', 'administrator@useraccess.net', true, User::hashPassword('abcd1234'), array('Everyone', 'Administrators'));
    $userProvider->createUser($admin);
}

$app = new RestApp($userProvider);
$app->run();