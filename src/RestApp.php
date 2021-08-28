<?php

namespace PragmaPHP\UserAccess;

use \Bramus\Router\Router;

class RestApp {

    private $router;
    private $userProvider;

    public function __construct(UserProviderInterface $userProvider, ?String $basePath = null) {

        $this->router = new \Bramus\Router\Router();
        if (!empty($basePath)) {
            $this->router->setBasePath($basePath);
        }
        $this->userProvider = $userProvider;

        //////////////////////////////////////////////////

        // $this->router->get('/v1/Session/Login', function (Request $request, Response $response, array $args) {
        //     $userAccess = $this->get('userAccess');
        //     $login = SessionAuthenticator::login($userAccess->getUserProvider(), $attributes['username'], $attributes['password']);
        //     $response->getBody()->write(json_encode($login));
        //     $response->withHeader('Content-Type', 'application/json');
        //     if ($login[SessionAuthenticator::UA_AUTH]) {
        //         return $response->withStatus(200);
        //     } else {
        //         return $response->withStatus(401);
        //     }
        // });

        // $this->router->post('/v1/Session/Login', function (Request $request, Response $response, array $args) {
        //     $userAccess = $this->get('userAccess');
        //     $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
        //     $login = SessionAuthenticator::login($userAccess->getUserProvider(), $attributes['username'], $attributes['password']);
        //     $response->getBody()->write(json_encode($login));
        //     $response->withHeader('Content-Type', 'application/json');
        //     if ($login[SessionAuthenticator::UA_AUTH]) {
        //         return $response->withStatus(200);
        //     } else {
        //         return $response->withStatus(401);
        //     }
        // });

        // $this->router->post('/v1/Session/Logout', function (Request $request, Response $response, array $args) {
        //     $userAccess = $this->get('userAccess');
        //     $userAccess->selfserviceLogout();
        // });

        //////////////////////////////////////////////////

        $this->router->get('/v1/Users', function () {
            // header('Content-Type: application/scim+json');
            $result = $this->userProvider->getUsers();
            echo json_encode($result);
        });

        $this->router->get('/v1/Users/{id}', function ($id) {
            // header('Content-Type: application/scim+json');
            $result = $this->userProvider->getUser($id);
            echo json_encode($result);
        });

    //     $this->router->post('/v1/Users', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         if (!array_key_exists('userName', $attributes)) {
    //             throw new \Exception(UserAccess::EXCEPTION_INVALID_UNIQUE_NAME);
    //         }
    //         if ($userAccess->getUserProvider()->isUniqueNameExisting($attributes['userName'])) {
    //             throw new \Exception(UserAccess::EXCEPTION_ENTRY_ALREADY_EXIST);
    //         }
    //         if (!empty($attributes['email'])) {
    //             $find = $userAccess->getUserProvider()->findUsers('email', $attributes['email']);
    //             if (!empty($find)) {
    //                 throw new \Exception(UserAccess::EXCEPTION_DUPLICATE_EMAIL);
    //             }
    //         }
    //         $entry = new User($attributes['userName']);
    //         $entry->setAttributes($attributes);
    //         $entry = $userAccess->getUserProvider()->createUser($entry);
    //         $response->getBody()->write(json_encode(self::filterPassword($entry->getAttributes())));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(201);
    //     });

    //     $this->router->post('/v1/Users/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         $entry = $userAccess->getUserProvider()->getUser($args['id']);
    //         if (!empty($attributes['email'])) {
    //             $email = trim(strtolower($attributes['email']));
    //             if (strcasecmp($email, $entry->getEmail()) != 0) {
    //                 $find = $userAccess->getUserProvider()->findUsers('email', $email);
    //                 if (!empty($find)) {
    //                     throw new \Exception(UserAccess::EXCEPTION_DUPLICATE_EMAIL);
    //                 }
    //             }
    //         }
    //         $entry->setAttributes($attributes);
    //         $userAccess->getUserProvider()->updateUser($entry);
    //         $response->getBody()->write(json_encode(self::filterPassword($entry->getAttributes())));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(200);
    //     });

    //     $this->router->delete('/v1/Users/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $userAccess->getUserProvider()->deleteUser($args['id']);
    //         return $response->withStatus(204);
    //     });

    //     //////////////////////////////////////////////////

    //     $this->router->get('/v1/Groups', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $entries = $userAccess->getGroupProvider()->getGroups();
    //         $result = [];
    //         foreach($entries as $entry){
    //             $result[] = $entry->getAttributes();
    //         }
    //         $response->getBody()->write(json_encode($result));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(200);
    //     });

    //     $this->router->get('/v1/Groups/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $entry = $userAccess->getGroupProvider()->getGroup($args['id']);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(201);
    //     });

    //     $this->router->post('/v1/Groups', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         $entry = new Group($attributes['uniqueName']);
    //         $entry->setAttributes($attributes);
    //         $entry = $userAccess->getGroupProvider()->createGroup($entry);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(201);
    //     });

    //     $this->router->post('/v1/Groups/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         $entry = $userAccess->getGroupProvider()->getGroup($args['id']);
    //         $entry->setAttributes($attributes);
    //         $entry = $userAccess->getGroupProvider()->updateGroup($entry);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(200);
    //     });

    //     $this->router->delete('/v1/Groups/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $userAccess->getGroupProvider()->deleteGroup($args['id']);
    //         return $response->withStatus(204);
    //     });
        
    //     //////////////////////////////////////////////////

    //     $this->router->get('/v1/Roles', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $entries = $userAccess->getRoleProvider()->getRoles();
    //         $result = [];
    //         foreach($entries as $entry){
    //             $result[] = $entry->getAttributes();
    //         }
    //         $response->getBody()->write(json_encode($result));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(200);
    //     });

    //     $this->router->get('/v1/Roles/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $entry = $userAccess->getRoleProvider()->getRole($args['id']);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(201);
    //     });

    //     $this->router->post('/v1/Roles', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         $entry = new Role($attributes['uniqueName']);
    //         $entry->setAttributes($attributes);
    //         $entry = $userAccess->getRoleProvider()->createRole($entry);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(201);
    //     });

    //     $this->router->post('/v1/Roles/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $attributes = filter_var_array($request->getParsedBody(), FILTER_SANITIZE_STRING);
    //         $entry = $userAccess->getRoleProvider()->getRole($args['id']);
    //         $entry->setAttributes($attributes);
    //         $entry = $userAccess->getRoleProvider()->updateRole($entry);
    //         $response->getBody()->write(json_encode($entry->getAttributes()));
    //         return $response->withHeader('Content-Type', 'application/scim+json')->withStatus(200);
    //     });

    //     $this->router->delete('/v1/Roles/{id}', function (Request $request, Response $response, array $args) {
    //         $userAccess = $this->get('userAccess');
    //         $userAccess->getRoleProvider()->deleteRole($args['id']);
    //         return $response->withStatus(204);
    //     });

    }

    public function run() {
        $this->router->run();
    }

    // public function getApp() {
    //     return $this->router;
    // }

    // //////////////////////////////////////////////////

    // private static function filterPassword(array $attributes): array {
    //     if (array_key_exists('passwordHash', $attributes)) {
    //         unset($attributes['passwordHash']);
    //     }
    //     return $attributes;
    // }

}