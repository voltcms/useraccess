<?php

namespace VoltCMS\UserAccess;

class SCIMApp
{

    //public function __construct(UserProviderInterface $userProvider, GroupProviderInterface $groupProvider)
    public function __construct(UserProviderInterface $userProvider)
    {

        //$scim20 = new SCIM($userProvider, $groupProvider);
        $scim20 = new SCIM($userProvider);

        /* SCIM 2.0 */
        if (preg_match('/^(.*)\/scim\/v2\/Users\/[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->getUser(explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1], file_get_contents('php://input'));
            elseif ($_SERVER['REQUEST_METHOD'] == "PUT")
                $scim20->putUser(file_get_contents('php://input'), explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            //elseif ($_SERVER['REQUEST_METHOD'] == "PATCH")
                //$scim20->patchUser(file_get_contents('php://input'), explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            elseif ($_SERVER['REQUEST_METHOD'] == "DELETE")
                $scim20->deleteUser(explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Users$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "POST")
                $scim20->createUser(file_get_contents('php://input'));
            elseif ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->listUsers($_GET);
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Groups\/[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->getGroup(explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1], file_get_contents('php://input'));
            elseif ($_SERVER['REQUEST_METHOD'] == "PUT")
                $scim20->putGroup(file_get_contents('php://input'), explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            //elseif ($_SERVER['REQUEST_METHOD'] == "PATCH")
                //$scim20->patchGroup(file_get_contents('php://input'), explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            elseif ($_SERVER['REQUEST_METHOD'] == "DELETE")
                $scim20->deleteGroup(explode("/", explode("?", $_SERVER['REQUEST_URI'])[0])[count(explode("/", @explode("?", $_SERVER['REQUEST_URI'])[0])) - 1]);
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Groups$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "POST")
                $scim20->createGroup(file_get_contents('php://input'));
            elseif ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->listGroups($_GET);
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/ServiceProviderConfigs?$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->showServiceProviderConfig();
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Me?$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if (in_array($_SERVER['REQUEST_METHOD'], array("GET", "POST", "PUT", "PATCH", "DELETE")))
                $scim20->throwError(400, "The requested endpoint is not available.");
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/ResourceTypes?$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->throwError(400, "The requested endpoint is not available.");
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Schemas?$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "GET")
                $scim20->throwError(400, "The requested endpoint is not available.");
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } elseif (preg_match('/^(.*)\/scim\/v2\/Bulk?$/', @explode("?", $_SERVER['REQUEST_URI'])[0])) {
            if ($_SERVER['REQUEST_METHOD'] == "POST")
                $scim20->throwError(400, "The requested endpoint is not available.");
            else
                $scim20->throwError(405, "The endpoint does not support the provided method.");
        } else {
            $scim20->throwError(400, "The requested endpoint is not available.");
        }
    }
}
