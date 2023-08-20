<?php

use \PHPUnit\Framework\TestCase;
use \VoltCMS\UserAccess\FileUserProvider;
use \VoltCMS\UserAccess\RestApp;

class RestAppTest extends TestCase
{

    private $app;
    private $userName = 'restu1';
    private $userId = '';
    private $groupName = 'restg1';
    private $groupId = '';
    private $roleName = 'restg1';
    private $roleId = '';

    public function setUp(): void
    {
        $userProvider = FileUserProvider::getInstance(array('directory' => 'testdata/user'));
        $this->app = new RestApp($userProvider);

        $_SERVER['SCRIPT_NAME'] = '/index.php';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    public function test_01_GetEmptyUsers()
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/v1/Users';
        ob_start();
        $this->app->run();
        $this->assertEquals('[]', ob_get_contents());
        ob_end_clean();
    }

    // public function test_02_GetUserFail() {
    //     $_SERVER['REQUEST_METHOD'] = 'GET';
    //     $_SERVER['REQUEST_URI'] = '/v1/Users/user';
    //     ob_start();
    //     $this->app->run();
    //     $result = ob_get_contents();
    //     $this->assertNotEmpty($result);
    //     $result = json_decode($result, true);
    //     $this->assertEquals('user', $result['userName']);
    //     ob_end_clean();
    // }

    // public function test110_create() {
    //     $req = $this->createRequest('POST', '/v1/Users');
    //     $attributes = array();
    //     $attributes['userName'] = $this->userName;
    //     $attributes['displayName'] = $this->userName;
    //     $req = $req->withParsedBody($attributes);
    //     $response = $this->app->getApp()->handle($req);
    //     $this->assertSame($response->getStatusCode(), 201);
    //     $attributes = json_decode($response->getBody(), true);
    //     $this->assertEquals(UserInterface::TYPE, $attributes['type']);
    //     $this->assertEquals($this->userName, $attributes['uniqueName']);
    //     $this->assertEquals($this->userName, $attributes['userName']);
    //     $this->assertNotEmpty($attributes['id']);
    //     $this->userId = $attributes['id'];
    // }

    // public function test_05_get() {
    //     $_SERVER['REQUEST_METHOD'] = 'GET';
    //     $_SERVER['REQUEST_URI'] = '/v1/Users/user';
    //     ob_start();
    //     $this->app->run();
    //     $result = ob_get_contents();
    //     $this->assertNotEmpty($result);
    //     $result = json_decode($result, true);
    //     $this->assertEquals('user', $result['userName']);
    //     ob_end_clean();
    // }

    // public function test111_get() {
    //     $id = $this->getEntryId(UserInterface::TYPE);
    //     $req = $this->createRequest('GET', '/v1/Users/' . $id);
    //     $response = $this->app->getApp()->handle($req);
    //     $this->assertSame($response->getStatusCode(), 201);
    //     $this->assertNotEmpty((string)$response->getBody());
    // }

    // public function test112_update() {
    //     $id = $this->getEntryId(UserInterface::TYPE);
    //     $req = $this->createRequest('POST', '/v1/Users/' . $id);
    //     $attributes = array();
    //     $attributes['displayName'] = $this->userName . '_test';
    //     $req = $req->withParsedBody($attributes);
    //     $response = $this->app->getApp()->handle($req);
    //     $this->assertSame($response->getStatusCode(), 200);
    // }

    // public function test115_delete() {
    //     $id = $this->getEntryId(UserInterface::TYPE);
    //     $req = $this->createRequest('DELETE', '/v1/Users/' . $id);
    //     $response = $this->app->getApp()->handle($req);
    //     $this->assertSame($response->getStatusCode(), 204);
    // }

    // public function test116_GetUserFail() {
    //     $req = $this->createRequest('GET', '/v1/Users/rest_u_1');
    //     $response = $this->app->getApp()->handle($req);
    //     $this->assertSame($response->getStatusCode(), 404);
    //     $this->assertNotEmpty((string)$response->getBody());
    // }

    // //////////////////////////////////////////////////

    // private function getEntryId(string $type): string {
    //     $req = $this->createRequest('GET', '/v1/' . $type . 's');
    //     $response = $this->app->getApp()->handle($req);
    //     $entries = json_decode($response->getBody(), true);
    //     $entry = current($entries);
    //     return $entry['id'];
    // }

}
