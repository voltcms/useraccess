<?php

namespace VoltCMS\UserAccess;

use \Exception;
use \Bramus\Router\Router;

class SCIM
{

    private $userProvider;
    private $groupProvider;
    private $sessionAuth;
    private $router;
    private $enforceAuthentication;
    private $loggedInUser;

    public function __construct(UserProviderInterface $userProvider, GroupProviderInterface $groupProvider)
    {
        $this->userProvider = $userProvider;
        $this->groupProvider = $groupProvider;
        $this->sessionAuth = SessionAuth::getInstance($this->userProvider);
        $this->router = new Router();
        $this->enforceAuthentication = false;
    }

    public function runRouter()
    {
        $this->router->set404(function () {
            //header('HTTP/1.1 404 Not Found');
            // ... do something special here
            $this->throwError(404, "Not Found");
        });

        if ($this->enforceAuthentication) {
            $this->loggedInUser = $this->sessionAuth->getLoggedInUser();
            if (!$this->loggedInUser) {
                $this->loggedInUser = HeaderAuth::checkBasicAuthentication($this->userProvider);
            }
            if (!$this->loggedInUser) {
                $this->throwError(401, "Unauthorized");
            } else {
                if (!$this->loggedInUser->isAdmin()) {
                    $this->throwError(403, "Forbidden");
                }
            }
        }

        // Users
        $this->router->get('/scim/users', function () {
            $this->listUsers($_GET);
        });
        $this->router->post('/scim/users', function () {
            $this->createUser(file_get_contents('php://input'));
        });
        $this->router->get('/scim/users/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->getUser($id);
        });
        $this->router->put('/scim/users/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->putUser(file_get_contents('php://input'), $id);
        });
        // $this->router->patch('/scim/users/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function($id) {
        //     $this->patchUser(file_get_contents('php://input'), $id);
        // });
        $this->router->delete('/scim/users/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->deleteUser($id);
        });

        // Groups
        $this->router->get('/scim/groups', function () {
            $this->listGroups($_GET);
        });
        $this->router->post('/scim/groups', function () {
            $this->createGroup(file_get_contents('php://input'));
        });
        $this->router->get('/scim/groups/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->getGroup($id);
        });
        $this->router->put('/scim/groups/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->putGroup(file_get_contents('php://input'), $id);
        });
        // $this->router->patch('/scim/groups/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function($id) {
        //     $this->patchGroup(file_get_contents('php://input'), $id);
        // });
        $this->router->delete('/scim/groups/([a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12})', function ($id) {
            $this->deleteGroup($id);
        });

        // Meta
        $this->router->get('/scim/ServiceProviderConfigs', function () {
            $this->showServiceProviderConfig();
        });

        // Other like Me, ResourceTypes, Schemas, Bulk

        $this->router->run();
    }

    public function createUser($requestBody)
    {
        $requestBody = $this->parseUserPayload(json_decode($requestBody, 1));
        $user = new User();
        $attributes = [];
        foreach ($requestBody as $key => $value) {
            // if ($key == "schemas")
            //     foreach ($value as $val)
            //         $this->db->addResourceSchema($userID, $val);
            if (in_array($key, array('id', 'groups', 'meta', 'schemas'))) {
                continue;
            }
            $attributes[$key] = $value;
        }
        $user->fromSCIM($attributes);
        try {
            $user = $this->userProvider->create($user);
        } catch (Exception $e) {
            error_log('Message: ' . $e->getMessage());
            switch ($e->getMessage()) {
                case 'EXCEPTION_USER_ALREADY_EXIST':
                    exit($this->throwError(409, "User with username " . $user->getUserName() . " already exists."));
                    break;
                case 'EXCEPTION_DUPLICATE_EMAIL':
                    exit($this->throwError(409, "User with email " . $user->getEmail() . " already exists."));
                    break;
                default:
                    exit($this->throwError(409, $e->getMessage()));
                    break;
            }
        }
        $payload = $user->toSCIM();
        unset($payload['_modified']);
        header("Content-Type: application/json", true, 201);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    public function getUser($userID, $isIncluded = '')
    {
        if (!$this->userProvider->exists('id', $userID)) {
            $this->throwError(404, "Selected user does not exist.");
        }
        $user = $this->userProvider->read('id', $userID);
        $payload = $user->toSCIM(true);
        header("Etag: " . $payload['meta']['version']);
        header("Last-Modified: " . gmdate("D, d M Y H:i:s", $payload['etagLastModified']) . " GMT");
        unset($payload['etagLastModified']);

        // $payload['schemas'] = $schemas;
        // $payload['id'] = $userID;

        // $payload['userName'] = $attributes['userName'];

        // if(isset($attributes['externalId']))
        //     $payload['externalId'] = $attributes['externalId'];    

        // if(isset($attributes['name']))
        //     $payload['name'] = $attributes['name'];

        // if(isset($attributes['displayName']))
        //     $payload['displayName'] = $attributes['displayName'];

        // if(isset($attributes['nickName']))
        //     $payload['nickName'] = $attributes['nickName'];

        // if(isset($attributes['profileUrl']))
        //     $payload['profileUrl'] = $attributes['profileUrl'];

        // if(isset($attributes['title']))
        //     $payload['title'] = $attributes['title'];

        // if(isset($attributes['userType']))
        //     $payload['userType'] = $attributes['userType'];

        // if(isset($attributes['preferredLanguage']))
        //     $payload['preferredLanguage'] = $attributes['preferredLanguage'];

        // if(isset($attributes['locale']))
        //     $payload['locale'] = $attributes['locale'];

        // if(isset($attributes['timezone']))
        //     $payload['timezone'] = $attributes['timezone'];

        // if(isset($attributes['active']))
        //     $payload['active'] = $attributes['active'];

        // if(isset($attributes['emails']))
        //     $payload['emails'] = $attributes['emails'];

        // if(isset($attributes['phoneNumbers']))
        //     $payload['phoneNumbers'] = $attributes['phoneNumbers'];

        // if(isset($attributes['ims']))
        //     $payload['ims'] = $attributes['ims'];

        // if(isset($attributes['photos']))
        //     $payload['photos'] = $attributes['photos'];

        // if(isset($attributes['addresses']))
        //     $payload['addresses'] = $attributes['addresses'];

        // $payload['groups'] = [];
        // foreach($groups as $group)
        // {
        //     $groupAttributes = $this->db->getResourceAttributes($group);    
        //     $grp = array("value" => $group, "displayName" => $groupAttributes['displayName']);
        //     $payload['groups'][] = $grp;
        // }
        // if(isset($attributes['entitlements']))
        //     $payload['entitlements'] = $attributes['entitlements'];    
        // if(isset($attributes['roles']))
        //     $payload['roles'] = $attributes['roles'];    
        // if(count($schemas) > 1)
        //     foreach($schemas as $schema)
        //     {
        //         if($schema == "urn:ietf:params:scim:schemas:core:2.0:User")
        //             continue;
        //         $payload[$schema] = $attributes[$schema];
        //     }
        // $payload['meta'] = array(
        //     "resourceType" => "User",
        //     "created" => gmdate("c", $metadata['created']),
        //     "lastModified" => gmdate("c", $metadata['lastUpdated']),
        //     "version" => $etag,
        //     "location" => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/users/" . $userID
        // );

        header("Content-Type: application/json", true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    public function listUsers($options)
    {
        $payload = [];
        if (array_key_exists('filter', $options)) {
            list($attribute, $value) = explode(' eq ', $options['filter']);
            if (str_starts_with($value, '"')) {
                $value = substr($value, 1);
            }
            if (str_ends_with($value, '"')) {
                $value = substr($value, 0, -1);
            }
            $users = $this->userProvider->find($attribute, $value);
        } else {
            $users = $this->userProvider->readAll();
        }
        $payload['schemas'] = array('urn:ietf:params:scim:api:messages:2.0:ListResponse');
        $payload['totalResults'] = count($users);
        $payload['startIndex'] = 1;
        $payload['itemsPerPage'] = count($users);
        // if((int) $options['startIndex'] > 0)
        //     $payload['startIndex'] = (int) $options['startIndex'];
        // if((int) $options['count'] > 0 && $options['count'] < $totalUsers)
        //     $payload['itemsPerPage'] = (int) $options['count'];
        // elseif($totalUsers > 0)
        //     $payload['itemsPerPage'] = $totalUsers;
        $payload['Resources'] = [];
        foreach ($users as $user) {
            $result = $user->toSCIM();
            unset($result['_modified']);
            $payload['Resources'][] = $result;
        }
        header('Content-Type: application/json', true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    public function putUser($requestBody, $userID)
    {
        $requestBody = $this->parseUserPayload(json_decode($requestBody, 1), true);
        if (!$this->userProvider->exists('id', $userID)) {
            $this->throwError(404, "Selected user does not exist.");
        }
        $user = $this->userProvider->read('id', $userID);
        if ($this->userProvider->exists('userName', $requestBody['userName'])) {
            $userCheck = $this->userProvider->read('userName', $requestBody['userName']);
            if ($userCheck->getId() != $user->getId()) {
                exit($this->throwError(400, "The username has already been taken by another user."));
            }
        }
        $attributes = [];
        foreach ($requestBody as $key => $value) {
            // if ($key == "schemas")
            //     foreach ($value as $val)
            //         $this->db->addResourceSchema($userID, $val);
            if (in_array($key, array('id', 'groups', 'meta', 'schemas'))) {
                continue;
            }
            $attributes[$key] = $value;
        }
        $user->fromSCIM($attributes);
        $user = $this->userProvider->update($user);
        $payload = $user->toSCIM();
        unset($payload['_modified']);
        header("Content-Type: application/json", true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    // public function patchUser($requestBody, $userID)
    // {
    //     $requestBody = json_decode($requestBody, 1);
    //     $userAttributes = $this->db->getResourceAttributes($userID);
    //     foreach ($requestBody as $key => $value) {
    //         if (in_array($key, array('schemas', 'id', 'groups')))
    //             continue;
    //         elseif ($key == "Operations" && is_array($value))
    //             foreach ($value as $val) {
    //                 if ($val['op'] == "replace") {
    //                     foreach ($val['value'] as $a => $v) {
    //                         if ($a == "userName")
    //                             if ($this->db->getUserID($v, "2.0") != $userID)
    //                                 exit($this->throwError(400, "Could not modify userName. There is already an existing user " . $a . " with the same name."));
    //                         $schemas = $this->db->getResourceSchemas($userID);
    //                         $this->db->deleteResourceAttribute($userID, $a);
    //                         $this->db->addResourceAttribute($userID, $a, json_encode($v));
    //                         if ($schemas[$a] != "")
    //                             $this->db->addResourceSchema($userID, $a);
    //                     }
    //                 } elseif ($val['op'] == "add")
    //                     foreach ($val['value'] as $a => $v) {
    //                         if ($a == "userName")
    //                             if ($this->db->getUserID($v, "2.0") != $userID)
    //                                 exit($this->throwError(400, "Could not modify userName. There is already an existing user " . $a . " with the same name."));
    //                         $this->db->addResourceAttribute($userID, $a, json_encode($v));
    //                     }
    //                 elseif ($val['op'] == "remove") {
    //                     $a = "todo";
    //                     $this->db->deleteResourceAttribute($userID, $a);
    //                 }
    //             }
    //     }
    //     $this->db->UpdateTimestamp($userID);
    //     header("Content-Type: application/json", true, 200);
    //     echo $this->getUser($userID, 1);
    // }

    public function deleteUser($userID)
    {
        if (!$this->userProvider->exists('id', $userID)) {
            $this->throwError(404, "Selected user does not exist.");
        }
        $this->userProvider->delete($userID);
        header("Content-Type: application/json", true, 204);
    }

    private function parseUserPayload($payload, $userCheck = false)
    {
        if (!$payload) {
            exit($this->throwError(400, "Incorrect request was sent to the SCIM server."));
        }
        if ($userCheck == false) {
            if ($this->userProvider->exists('userName', $payload['userName'])) {
                exit($this->throwError(409, "User with username " . $payload['userName'] . " already exists."));
            }
        }
        if ($payload['schemas'] == "") {
            exit($this->throwError(400, "No schema was found in the request for user creation process."));
        }
        if (!in_array("urn:ietf:params:scim:schemas:core:2.0:User", $payload['schemas'])) {
            exit($this->throwError(400, "Incorrect schema was sent in the request for user creation process."));
        }
        $schemas = $payload['schemas'];
        foreach ($schemas as $schema) {
            if ($schema == "urn:ietf:params:scim:schemas:core:2.0:User") {
                continue;
            }
            if ($payload[$schema] == "") {
                exit($this->throwError(400, "The schema '" . htmlentities($schema, ENT_QUOTES) . "' was defined in the request, but it did not have a body set."));
            }
        }
        if (!array_key_exists('userName', $payload) || $payload['userName'] == "") {
            exit($this->throwError(400, "The 'userName' field was not present in the request."));
        }
        if (!is_string($payload['userName'])) {
            exit($this->throwError(400, "The 'userName' field sent in the request must be a string."));
        }
        if (array_key_exists('name', $payload) && $payload['name'] != "") {
            if (!is_array($payload['name'])) {
                exit($this->throwError(400, "The 'name' field was sent incorrectly in the request."));
            } else {
                foreach ($payload['name'] as $key => $value) {
                    if (!in_array($key, array("formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"))) {
                        exit($this->throwError(400, "An unexpected field, '" . htmlentities($key, ENT_QUOTES) . "', was found under the 'name' field in the request."));
                    } elseif (!is_string($value)) {
                        exit($this->throwError(400, "The field '" . htmlentities($key, ENT_QUOTES) . "' contains a value that is not string."));
                    }
                }
            }
        }
        if (array_key_exists('displayName', $payload) && $payload['displayName'] != "") {
            if (!is_string($payload['displayName'])) {
                exit($this->throwError(400, "The 'displayName' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('nickName', $payload) && $payload['nickName'] != "") {
            if (!is_string($payload['nickName'])) {
                exit($this->throwError(400, "The 'nickName' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('profileUrl', $payload) && $payload['profileUrl'] != "") {
            if (!is_string($payload['profileUrl'])) {
                exit($this->throwError(400, "The 'profileUrl' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('title', $payload) && $payload['title'] != "") {
            if (!is_string($payload['title'])) {
                exit($this->throwError(400, "The 'title' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('userType', $payload) && $payload['userType'] != "") {
            if (!is_string($payload['userType'])) {
                exit($this->throwError(400, "The 'userType' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('preferredLanguage', $payload) && $payload['preferredLanguage'] != "") {
            if (!is_string($payload['preferredLanguage'])) {
                exit($this->throwError(400, "The 'preferredLanguage' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('locale', $payload) && $payload['locale'] != "") {
            if (!is_string($payload['locale'])) {
                exit($this->throwError(400, "The 'locale' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('timezone', $payload) && $payload['timezone'] != "") {
            if (!is_string($payload['timezone'])) {
                exit($this->throwError(400, "The 'timezone' field was sent incorrectly in the request."));
            }
        }
        if (array_key_exists('active', $payload) && $payload['active'] != "") {
            if (!is_bool($payload['active']) && !is_integer($payload['active'])) {
                exit($this->throwError(400, "The 'active' field was sent incorrectly in the request."));
            }
        }
        if (!array_key_exists('active', $payload) || $payload['active'] == "" || $payload['active'] == 0) {
            $payload['active'] = false;
        }
        if (array_key_exists('active', $payload) && $payload['active'] == 1) {
            $payload['active'] = true;
        }
        if (array_key_exists('emails', $payload) && $payload['emails'] != "") {
            if (!is_array($payload['emails'])) {
                exit($this->throwError(400, "The 'emails' field was sent incorrectly in the request."));
            }
        } else {
            foreach ($payload['emails'] as $emails) {
                if (!is_array($emails)) {
                    exit($this->throwError(400, "The 'emails' field was sent incorrectly in the request."));
                }
            }
        }
        if (array_key_exists('phoneNumbers', $payload) && $payload['phoneNumbers'] != "") {
            if (!is_array($payload['phoneNumbers'])) {
                exit($this->throwError(400, "The 'phoneNumbers' field was sent incorrectly in the request."));
            }
        } else {
            foreach ($payload['phoneNumbers'] as $phoneNumbers) {
                if (!is_array($phoneNumbers)) {
                    exit($this->throwError(400, "The 'phoneNumbers' field was sent incorrectly in the request."));
                }
            }
        }
        if (array_key_exists('ims', $payload) && $payload['ims'] != "") {
            if (!is_array($payload['ims'])) {
                exit($this->throwError(400, "The 'ims' field was sent incorrectly in the request."));
            }
        } else {
            foreach ($payload['ims'] as $ims) {
                if (!is_array($ims)) {
                    exit($this->throwError(400, "The 'ims' field was sent incorrectly in the request."));
                }
            }
        }
        if (array_key_exists('photos', $payload) && $payload['photos'] != "") {
            if (!is_array($payload['photos'])) {
                exit($this->throwError(400, "The 'photos' field was sent incorrectly in the request."));
            }
        } else {
            foreach ($payload['photos'] as $photos) {
                if (!is_array($photos)) {
                    exit($this->throwError(400, "The 'photos' field was sent incorrectly in the request."));
                }
            }
        }
        if (array_key_exists('addresses', $payload) && $payload['addresses'] != "") {
            if (!is_array($payload['addresses'])) {
                exit($this->throwError(400, "The 'addresses' field was sent incorrectly in the request."));
            }
        } else {
            foreach ($payload['addresses'] as $addresses) {
                if (!is_array($addresses)) {
                    exit($this->throwError(400, "The 'addresses' field was sent incorrectly in the request."));
                }
            }
        }
        if (array_key_exists('entitlements', $payload) && $payload['entitlements'] != "") {
            if (!is_array($payload['entitlements'])) {
                exit($this->throwError(400, "The 'entitlements' field was sent incorrectly in the request."));
            } else {
                foreach ($payload['entitlements'] as $entitlements) {
                    if (!is_array($entitlements)) {
                        exit($this->throwError(400, "The 'entitlements' field was sent incorrectly in the request."));
                    }
                }
            }
        }
        if (array_key_exists('roles', $payload) && $payload['roles'] != "") {
            if (!is_array($payload['roles'])) {
                exit($this->throwError(400, "The 'roles' field was sent incorrectly in the request."));
            } else {
                foreach ($payload['roles'] as $roles) {
                    if (!is_array($roles)) {
                        exit($this->throwError(400, "The 'roles' field was sent incorrectly in the request."));
                    }
                }
            }
        }
        foreach ($payload as $key => $value) {
            if (!in_array($key, array('schemas', 'id', 'externalId', 'meta', 'userName', 'name', 'displayName', 'nickName', 'profileUrl', 'title', 'userType', 'preferredLanguage', 'locale', 'timezone', 'active', 'password', 'emails', 'phoneNumbers', 'ims', 'photos', 'addresses', 'groups', 'entitlements', 'roles', 'x509Certificates')) && !in_array($key, $schemas)) {
                exit($this->throwError(400, "The '" . htmlentities($key, ENT_QUOTES) . "' field must not be present in the request."));
            }
        }
        // if ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] != "")
        //     if ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber']))
        //         exit($this->throwError(400, "The 'employeeNumber' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter']))
        //         exit($this->throwError(400, "The 'costCenter' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization']))
        //         exit($this->throwError(400, "The 'organization' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division']))
        //         exit($this->throwError(400, "The 'division' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']))
        //         exit($this->throwError(400, "The 'department' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId']))
        //         exit($this->throwError(400, "The 'manager.managerId' field contains an invalid value in the request."));
        //     elseif ($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['displayName'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['displayName']))
        //         exit($this->throwError(400, "The 'manager.displayName' field contains an invalid value in the request."));
        return $payload;
    }

    public function createGroup($requestBody)
    {
        $requestBody = $this->parseGroupPayload(json_decode($requestBody, 1));
        $group = new Group();
        $attributes = [];
        foreach ($requestBody as $key => $value) {
            // if ($key == "schemas")
            //     foreach ($value as $val)
            //         $this->db->addResourceSchema($groupID, $val);
            if (in_array($key, array('id', 'meta', 'schemas'))) {
                continue;
            }
            // if ($key == "members")
            //     foreach ($value as $member)
            //         $this->db->addGroupMember($groupID, $member['value']);
            $attributes[$key] = $value;
        }
        $group->fromSCIM($attributes);
        $group = $this->groupProvider->create($group);
        $payload = $group->toSCIM();
        unset($payload['_modified']);
        header("Content-Type: application/json", true, 201);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }


    public function getGroup($groupID, $isIncluded = '')
    {
        if (!$this->groupProvider->exists('id', $groupID)) {
            exit($this->throwError(404, "This group does not exist."));
        }
        $group = $this->groupProvider->read('id', $groupID);
        $payload = $group->toSCIM(true);
        header("Etag: " . $payload['meta']['version']);
        header("Last-Modified: " . gmdate("D, d M Y H:i:s", $payload['etagLastModified']) . " GMT");
        unset($payload['etagLastModified']);
        header("Content-Type: application/json", true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));

        // if (!$this->db->groupExists($groupID, "2.0"))
        //     exit($this->throwError(404, "This group does not exist."));
        // $attributes = $this->db->getResourceAttributes($groupID);
        // $metadata = $this->db->getMetadata($groupID);
        // $schemas = $this->db->getResourceSchemas($groupID);
        // $members = $this->db->getGroupMembers($groupID);
        // $etag = md5(json_encode($attributes) . json_encode($schemas) . json_encode($metadata) . json_encode($members));
        // if ($isIncluded == '') {
        //     header("Etag: " . $etag);
        //     header("Last-Modified: " . gmdate("D, d M Y H:i:s", $metadata['lastUpdated']) . " GMT");
        // }
        // $payload = [];
        // $payload['schemas'] = $schemas;
        // $payload['id'] = $groupID;
        // $payload['displayName'] = $attributes['displayName'];
        // $payload['members'] = [];
        // foreach ($members as $member) {
        //     $userAttributes = $this->db->getResourceAttributes($member);
        //     $user = array('value' => $member, 'display' => $userAttributes['userName']);
        //     $payload['members'][] = $user;
        // }
        // if (count($schemas) > 1)
        //     foreach ($schemas as $schema) {
        //         if ($schema == "urn:ietf:params:scim:schemas:core:2.0:Group")
        //             continue;
        //         $payload[$schema] = $attributes[$schema];
        //     }
        // $payload['meta'] = array(
        //     "resourceType" => "Group",
        //     "created" => gmdate("c", $metadata['created']),
        //     "lastModified" => gmdate("c", $metadata['lastUpdated']),
        //     "version" => $etag,
        //     "location" => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/groups/" . $groupID
        // );
        // if ($isIncluded == '')
        //     header("Content-Type: application/json", true, 200);
        // if ($isIncluded != '')
        //     return preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
        // else
        //     echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    public function listGroups($options)
    {
        $payload = [];
        $groups = $this->groupProvider->readAll();
        $payload['schemas'] = array('urn:ietf:params:scim:api:messages:2.0:ListResponse');
        $payload['totalResults'] = count($groups);
        $payload['startIndex'] = 1;
        $payload['itemsPerPage'] = count($groups);
        // if((int) $options['startIndex'] > 0)
        //     $payload['startIndex'] = (int) $options['startIndex'];
        // if((int) $options['count'] > 0 && $options['count'] < $totalUsers)
        //     $payload['itemsPerPage'] = (int) $options['count'];
        // elseif($totalUsers > 0)
        //     $payload['itemsPerPage'] = $totalUsers;
        $payload['Resources'] = [];
        foreach ($groups as $group) {
            $result = $group->toSCIM();
            unset($result['_modified']);
            $payload['Resources'][] = $result;
        }
        header('Content-Type: application/json', true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    // public function patchGroup($requestBody, $groupID)
    // {
    //     $requestBody = json_decode($requestBody, 1);
    //     $groupAttributes = $this->db->getResourceAttributes($groupID);
    //     foreach ($requestBody as $key => $value) {
    //         if (in_array($key, array('schemas', 'id', 'groups')))
    //             continue;
    //         elseif ($key == "Operations" && is_array($value))
    //             foreach ($value as $val) {
    //                 if ($val['path'] == "members") {
    //                     if ($val['op'] == "replace") {
    //                         $this->db->deleteAllGroupMembership($groupID);
    //                         foreach ($val['value'] as $members)
    //                             $this->db->addGroupMember($groupID, $members['value']);
    //                     } elseif ($val['op'] == "add")
    //                         foreach ($val['value'] as $members)
    //                             $this->db->addGroupMember($groupID, $members['value']);
    //                     elseif ($val['op'] == "remove")
    //                         foreach ($val['value'] as $members)
    //                             $this->db->deleteGroupMembership($groupID, $members['value']);
    //                 } else {
    //                     if ($val['op'] == "replace") {
    //                         foreach ($val['value'] as $a => $v) {
    //                             $schemas = $this->db->getResourceSchemas($groupID);
    //                             $this->db->deleteResourceAttribute($groupID, $a);
    //                             $this->db->addResourceAttribute($groupID, $a, json_encode($v));
    //                             if ($schemas[$a] != "")
    //                                 $this->db->addResourceSchema($groupID, $a);
    //                         }
    //                     } elseif ($val['op'] == "add")
    //                         foreach ($val['value'] as $a => $v) {
    //                             $this->db->addResourceAttribute($groupID, $a, json_encode($v));
    //                         }
    //                     elseif ($val['op'] == "remove") {
    //                         if (substr($val['path'], 0, 7) == "members") {
    //                             preg_match('/[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}/', $val['path'], $matches);
    //                             $this->db->deleteGroupMembership($groupID, $matches[0]);
    //                         } else {
    //                             $a = "todo";
    //                             $this->db->deleteResourceAttribute($groupID, $a);
    //                         }
    //                     }
    //                 }
    //             }
    //     }
    //     $this->db->updateTimestamp($groupID);
    //     header("Content-Type: application/json", true, 200);
    //     $this->getGroup($groupID);
    // }

    public function putGroup($requestBody, $groupID)
    {
        $requestBody = $this->parseGroupPayload(json_decode($requestBody, 1), true);
        $group = $this->groupProvider->read('id', $groupID);
        if ($this->groupProvider->exists('displayName', $requestBody['displayName'])) {
            $groupCheck = $this->groupProvider->read('displayName', $requestBody['displayName']);
            if ($groupCheck->getId() != $group->getId()) {
                exit($this->throwError(400, "The displayname has already been taken by another group."));
            }
        }
        $attributes = [];
        foreach ($requestBody as $key => $value) {
            // if ($key == "schemas")
            //     foreach ($value as $val)
            //         $this->db->addResourceSchema($groupID, $val);
            if (in_array($key, array('id', 'meta', 'schemas'))) {
                continue;
            }
            // if ($key == "members") {
            //     $group = $this->groupProvider->read('id', $groupID);
            //     $group->addMembers($value);
            // }
            $attributes[$key] = $value;
        }
        $group->fromSCIM($attributes);
        $group = $this->groupProvider->update($group);
        $payload = $group->toSCIM();
        unset($payload['_modified']);
        header("Content-Type: application/json", true, 200);
        echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
    }

    public function deleteGroup($groupID)
    {
        if (!$this->groupProvider->exists('id', $groupID)) {
            $this->throwError(404, "Group selected does not exist.");
        }
        $group = $this->groupProvider->read('id', $groupID);
        if ($group->getDisplayName() == "Administrators") {
            $this->throwError(403, "Forbidden");
        }
        $this->groupProvider->delete($groupID);
        header("Content-Type: application/json", true, 204);
    }

    private function parseGroupPayload($payload, $groupCheck = false)
    {
        if (!$payload) {
            exit($this->throwError(400, "Incorrect request was sent to the SCIM server."));
        }
        if ($groupCheck == false) {
            if ($this->groupProvider->exists('displayName', $payload['displayName'])) {
                exit($this->throwError(409, "Group with displayname " . $payload['displayName'] . " already exists."));
            }
        }
        if ($payload['schemas'] == "" || !in_array("urn:ietf:params:scim:schemas:core:2.0:Group", $payload['schemas'])) {
            exit($this->throwError(400, "Incorrect schema was provided in the request."));
        }
        if ($payload['displayName'] == "") {
            exit($this->throwError(400, "No displayName was provided in the request."));
        }
        return $payload;
    }

    public function showServiceProviderConfig()
    {
        header("Content-Type: application/json", true, 200);
        $payload = [];
        $payload['schemas'] = array("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
        $payload['patch'] = array("supported" => false);
        $payload['bulk'] = array("supported" => false, "maxOperations" => 0, "maxPayloadSize" => 0);
        $payload['filter'] = array("supported" => false, "maxResults" => 0);
        $payload['changePassword'] = array("supported" => true);
        $payload['sort'] = array("supported" => false);
        $payload['etag'] = array("supported" => true);
        $payload['authenticationSchemes'] = array(
            // array("name" => "OAuth Bearer Token", "description" => "Authentication Scheme using the OAuth Bearer Token Standard", "type" => "oauthbearertoken"),
            array("name" => "HTTP Basic", "description" => "Authentication Scheme using the Http Basic Standard", "type" => "httpbasic")
        );
        echo json_encode($payload);
    }

    public function throwError($statusCode, $description)
    {
        header("Content-Type: application/json", true, $statusCode);
        exit(json_encode(
            array(
                'schemas' => array("urn:ietf:params:scim:api:messages:2.0:Error"),
                'detail' => $description,
                'status' => $statusCode
            )
        ));
    }
}
