<?php

namespace VoltCMS\UserAccess;

class SCIM
{
	protected $db;
	private $userProvider;
    private $groupProvider;
	
	//function __construct(UserProviderInterface $userProvider, GroupProviderInterface $groupProvider)
	function __construct(UserProviderInterface $userProvider)
	{
		//$this->db = new Database();
		$this->userProvider = $userProvider;
		//$this->groupProvider = $groupProvider;
	}
	
	public function createUser($requestBody)
	{
		$this->parseUserPayload($requestBody);
		$requestBody = json_decode($requestBody, 1);
		
		if($requestBody['active'] == "")
			$requestBody['active'] = 1;
		
		$userID = $this->db->createResource("2.0", 0);
		
		foreach($requestBody as $key => $value)
		{
			if($key == "schemas")
				foreach($value as $val)
					$this->db->addResourceSchema($userID, $val);
			
			if(in_array($key,array('id', 'groups', 'meta','schemas')))
				continue;
			
			$this->db->addResourceAttribute($userID, $key, json_encode($value));
		}
		
		header("Content-Type: application/json", true, 201);
		echo $this->getUser($userID, 1);
	}
	
	public function getUser($userID, $isIncluded='')
	{
		if(!$this->db->userExists($userID, "2.0"))
			exit($this->throwError(404, "This user does not exist."));
		
		$attributes = $this->db->getResourceAttributes($userID);
		$schemas = $this->db->getResourceSchemas($userID);
		$metadata = $this->db->getMetadata($userID);
		$groups = $this->db->getGroupMemberships($userID);
		$etag = md5(json_encode($attributes) . json_encode($schemas) . json_encode($metadata) . json_encode($groups));
		
		if($isIncluded == '')
		{
			header("Etag: " . $etag);
			header("Last-Modified: ".gmdate("D, d M Y H:i:s", $metadata['lastUpdated'])." GMT");
		}

		$payload = array();		
		$payload['schemas'] = $schemas;
		$payload['id'] = $userID;
		
		$payload['userName'] = $attributes['userName'];
		
		if(isset($attributes['externalId']))
			$payload['externalId'] = $attributes['externalId'];	
		
		if(isset($attributes['name']))
			$payload['name'] = $attributes['name'];
		
		if(isset($attributes['displayName']))
			$payload['displayName'] = $attributes['displayName'];
		
		if(isset($attributes['nickName']))
			$payload['nickName'] = $attributes['nickName'];
		
		if(isset($attributes['profileUrl']))
			$payload['profileUrl'] = $attributes['profileUrl'];
		
		if(isset($attributes['title']))
			$payload['title'] = $attributes['title'];
		
		if(isset($attributes['userType']))
			$payload['userType'] = $attributes['userType'];
		
		if(isset($attributes['preferredLanguage']))
			$payload['preferredLanguage'] = $attributes['preferredLanguage'];
		
		if(isset($attributes['locale']))
			$payload['locale'] = $attributes['locale'];
		
		if(isset($attributes['timezone']))
			$payload['timezone'] = $attributes['timezone'];
		
		if(isset($attributes['active']))
			$payload['active'] = $attributes['active'];
		
		if(isset($attributes['emails']))
			$payload['emails'] = $attributes['emails'];
		
		if(isset($attributes['phoneNumbers']))
			$payload['phoneNumbers'] = $attributes['phoneNumbers'];
		
		if(isset($attributes['ims']))
			$payload['ims'] = $attributes['ims'];
		
		if(isset($attributes['photos']))
			$payload['photos'] = $attributes['photos'];
		
		if(isset($attributes['addresses']))
			$payload['addresses'] = $attributes['addresses'];
		
		$payload['groups'] = array();
		foreach($groups as $group)
		{
			$groupAttributes = $this->db->getResourceAttributes($group);	
			$grp = array("value" => $group, "displayName" => $groupAttributes['displayName']);
			$payload['groups'][] = $grp;
		}
		
		if(isset($attributes['entitlements']))
			$payload['entitlements'] = $attributes['entitlements'];	
		
		if(isset($attributes['roles']))
			$payload['roles'] = $attributes['roles'];	
		
		if(count($schemas) > 1)
			foreach($schemas as $schema)
			{
				if($schema == "urn:ietf:params:scim:schemas:core:2.0:User")
					continue;
				
				$payload[$schema] = $attributes[$schema];
			}
		
		$payload['meta'] = array(
			"resourceType" => "User",
			"created" => gmdate("c", $metadata['created']),
			"lastModified" => gmdate("c", $metadata['lastUpdated']),
			"version" => $etag,
			"location" => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/v2/Users/" . $userID
		);

		if($isIncluded == '')
			header("Content-Type: application/json", true, 200);
		
		if($isIncluded != '')
			return preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
		else
			echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
	}
	
	public function listUsers($options)
	{
		$payload = array();

		$users = $this->userProvider->readAll();

		//$users = $this->db->listResources("2.0", 0, $options, false);
		//$totalUsers = $this->db->listResources("2.0", 0, $options, true);
		
		$payload['schemas'] = array('urn:ietf:params:scim:api:messages:2.0:ListResponse');
		$payload['totalResults'] = count($users);
		$payload['startIndex'] = 1;
		$payload['itemsPerPage'] = 0;
		
		// if((int) $options['startIndex'] > 0)
		// 	$payload['startIndex'] = (int) $options['startIndex'];
		
		// if((int) $options['count'] > 0 && $options['count'] < $totalUsers)
		// 	$payload['itemsPerPage'] = (int) $options['count'];
		// elseif($totalUsers > 0)
		// 	$payload['itemsPerPage'] = $totalUsers;
		
		$payload['Resources'] = array();

		// foreach($users as $user)
		// 	$payload['Resources'][] = json_decode($this->getUser($user, 1));
		foreach($users as $user) {
			$payload['Resources'][] = json_decode($user->toJson(), 1);
		}
		
		header("Content-Type: application/json", true, 200);
		echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
	}
	
	public function putUser($requestBody, $userID)
	{
		$this->parseUserPayload($requestBody, true);
		$requestBody = json_decode($requestBody, 1);
		
		if($requestBody['active'] == "")
			$requestBody['active'] = 1;
		
		if($this->db->getUserID($requestBody['userName'], "2.0") != $userID)
			exit($this->throwError(400, "The username has already been taken by another user."));
		
		$this->db->deleteResourceSchemas($userID);
		$this->db->deleteResourceAttributes($userID);
		
		foreach($requestBody as $key => $value)
		{
			if($key == "schemas")
				foreach($value as $val)
					$this->db->addResourceSchema($userID, $val);
			
			if(in_array($key,array('id', 'groups', 'meta')))
				continue;
			
			$this->db->addResourceAttribute($userID, $key, json_encode($value));
		}
		
		$this->db->UpdateTimestamp($userID);
		
		header("Content-Type: application/json", true, 200);
		echo $this->getUser($userID, 1);
	}
	
	public function patchUser($requestBody, $userID)
	{
		$requestBody = json_decode($requestBody, 1);
		$userAttributes = $this->db->getResourceAttributes($userID);
		
		foreach($requestBody as $key => $value)
		{			
			if(in_array($key,array('schemas', 'id', 'groups')))
				continue;
			
			elseif($key == "Operations" && is_array($value))
				foreach($value as $val)
				{
					if($val['op'] == "replace")
					{
						foreach($val['value'] as $a => $v)
						{
							if($a == "userName")
								if($this->db->getUserID($v, "2.0") != $userID)
									exit($this->throwError(400, "Could not modify userName. There is already an existing user " . $a . " with the same name."));
							
							$schemas = $this->db->getResourceSchemas($userID);
							
							$this->db->deleteResourceAttribute($userID, $a);
							$this->db->addResourceAttribute($userID, $a, json_encode($v));
							
							if($schemas[$a] != "")
								$this->db->addResourceSchema($userID, $a);
						}
					}elseif($val['op'] == "add")
						foreach($val['value'] as $a => $v)
						{
							if($a == "userName")
								if($this->db->getUserID($v, "2.0") != $userID)
									exit($this->throwError(400, "Could not modify userName. There is already an existing user " . $a . " with the same name."));
							
							$this->db->addResourceAttribute($userID, $a, json_encode($v));
						}
					elseif($val['op'] == "remove") {
						$a = "todo";
						$this->db->deleteResourceAttribute($userID, $a);
					}
				}
		}
		
		$this->db->UpdateTimestamp($userID);
		
		header("Content-Type: application/json", true, 200);
		echo $this->getUser($userID, 1);
	}
	
	private function parseUserPayload($payload, $userCheck=false)
	{
		$payload = json_decode($payload, 1);
		
		if(!$payload)
			exit($this->throwError(400, "Incorrect request was sent to the SCIM server."));
		
		if($userCheck == false)
			if($this->db->userExists($payload['userName'], "2.0"))
				exit($this->throwError(409, "User already exists in the database."));
		
		if($payload['schemas'] == "")
			exit($this->throwError(400, "No schema was found in the request for user creation process."));
		
		if(!in_array("urn:ietf:params:scim:schemas:core:2.0:User", $payload['schemas']))
			exit($this->throwError(400, "Incorrect schema was sent in the request for user creation process."));
		
		$schemas = $payload['schemas'];
		
		foreach($schemas as $schema)
		{
			if($schema == "urn:ietf:params:scim:schemas:core:2.0:User")
				continue;
			
			if($payload[$schema] == "")
				exit($this->throwError(400, "The schema '" . htmlentities($schema, ENT_QUOTES) . "' was defined in the request, but it did not have a body set."));
		}
		
		if($payload['userName'] == "")
			exit($this->throwError(400, "The 'userName' field was not present in the request."));
		
		if(!is_string($payload['userName']))
			exit($this->throwError(400, "The 'userName' field sent in the request must be a string."));
		
		if($payload['name'] != "")
			if(!is_array($payload['name']))
				exit($this->throwError(400, "The 'name' field was sent incorrectly in the request."));
			else
				foreach($payload['name'] as $key => $value)
					if(!in_array($key, array("formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix")))
						exit($this->throwError(400, "An unexpected field, '" . htmlentities($key, ENT_QUOTES) . "', was found under the 'name' field in the request."));
					elseif(!is_string($value))
						exit($this->throwError(400, "The field '" . htmlentities($key, ENT_QUOTES) . "' contains a value that is not string."));
						
		if($payload['displayName'] != "")
			if(!is_string($payload['displayName']))
				exit($this->throwError(400, "The 'displayName' field was sent incorrectly in the request."));
				
		if($payload['nickName'] != "")
			if(!is_string($payload['nickName']))
				exit($this->throwError(400, "The 'nickName' field was sent incorrectly in the request."));
			
		if($payload['profileUrl'] != "")
			if(!is_string($payload['profileUrl']))
				exit($this->throwError(400, "The 'profileUrl' field was sent incorrectly in the request."));
			
		if($payload['title'] != "")
			if(!is_string($payload['title']))
				exit($this->throwError(400, "The 'title' field was sent incorrectly in the request."));
		
		if($payload['userType'] != "")
			if(!is_string($payload['userType']))
				exit($this->throwError(400, "The 'userType' field was sent incorrectly in the request."));
			
		if($payload['preferredLanguage'] != "")
			if(!is_string($payload['preferredLanguage']))
				exit($this->throwError(400, "The 'preferredLanguage' field was sent incorrectly in the request."));
			
		if($payload['locale'] != "")
			if(!is_string($payload['locale']))
				exit($this->throwError(400, "The 'locale' field was sent incorrectly in the request."));
			
		if($payload['timezone'] != "")
			if(!is_string($payload['timezone']))
				exit($this->throwError(400, "The 'timezone' field was sent incorrectly in the request."));
		
		
		if($payload['active'] != "")
			if(!is_bool($payload['active']) && !is_integer($payload['active']))
				exit($this->throwError(400, "The 'active' field was sent incorrectly in the request."));
			
		if($payload['emails'] != "")
			if(!is_array($payload['emails']))
				exit($this->throwError(400, "The 'emails' field was sent incorrectly in the request."));
			else
				foreach($payload['emails'] as $emails)
					if(!is_array($emails))
						exit($this->throwError(400, "The 'emails' field was sent incorrectly in the request."));
					
		if($payload['phoneNumbers'] != "")
			if(!is_array($payload['phoneNumbers']))
				exit($this->throwError(400, "The 'phoneNumbers' field was sent incorrectly in the request."));
			else
				foreach($payload['phoneNumbers'] as $phoneNumbers)
					if(!is_array($phoneNumbers))
						exit($this->throwError(400, "The 'phoneNumbers' field was sent incorrectly in the request."));
		
		if($payload['ims'] != "")
			if(!is_array($payload['ims']))
				exit($this->throwError(400, "The 'ims' field was sent incorrectly in the request."));
			else
				foreach($payload['ims'] as $ims)
					if(!is_array($ims))
						exit($this->throwError(400, "The 'ims' field was sent incorrectly in the request."));
				
		if($payload['photos'] != "")
			if(!is_array($payload['photos']))
				exit($this->throwError(400, "The 'photos' field was sent incorrectly in the request."));
			else
				foreach($payload['photos'] as $photos)
					if(!is_array($photos))
						exit($this->throwError(400, "The 'photos' field was sent incorrectly in the request."));
				
		if($payload['addresses'] != "")
			if(!is_array($payload['addresses']))
				exit($this->throwError(400, "The 'addresses' field was sent incorrectly in the request."));
			else
				foreach($payload['addresses'] as $addresses)
					if(!is_array($addresses))
						exit($this->throwError(400, "The 'addresses' field was sent incorrectly in the request."));
					
		if($payload['entitlements'] != "")
			if(!is_array($payload['entitlements']))
				exit($this->throwError(400, "The 'entitlements' field was sent incorrectly in the request."));
			else
				foreach($payload['entitlements'] as $entitlements)
					if(!is_array($entitlements))
						exit($this->throwError(400, "The 'entitlements' field was sent incorrectly in the request."));

		if($payload['roles'] != "")
			if(!is_array($payload['roles']))
				exit($this->throwError(400, "The 'roles' field was sent incorrectly in the request."));
			else
				foreach($payload['roles'] as $roles)
					if(!is_array($roles))
						exit($this->throwError(400, "The 'roles' field was sent incorrectly in the request."));				

				
		foreach($payload as $key => $value)
			if(!in_array($key,array('schemas', 'id', 'externalId', 'meta', 'userName', 'name', 'displayName', 'nickName', 'profileUrl', 'title', 'userType', 'preferredLanguage', 'locale', 'timezone', 'active', 'password', 'emails', 'phoneNumbers', 'ims', 'photos', 'addresses', 'groups', 'entitlements', 'roles', 'x509Certificates')) && !in_array($key, $schemas))
				exit($this->throwError(400, "The '" . htmlentities($key, ENT_QUOTES) . "' field must not be present in the request."));
			
		if($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] != "")
			if($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['employeeNumber']))
				exit($this->throwError(400, "The 'employeeNumber' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['costCenter']))
				exit($this->throwError(400, "The 'costCenter' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['organization']))
				exit($this->throwError(400, "The 'organization' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['division']))
				exit($this->throwError(400, "The 'division' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['department']))
				exit($this->throwError(400, "The 'department' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId']) && !is_numeric($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['managerId']))
				exit($this->throwError(400, "The 'manager.managerId' field contains an invalid value in the request."));
			elseif($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['displayName'] != "" && !is_string($payload['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']['manager']['displayName']))
				exit($this->throwError(400, "The 'manager.displayName' field contains an invalid value in the request."));				
	}
	
	public function createGroup($requestBody)
	{
		$this->parseGroupPayload($requestBody);
		$requestBody = json_decode($requestBody, 1);
		
		$groupID = $this->db->createResource("2.0", 1);
		
		foreach($requestBody as $key => $value)
		{
			if($key == "schemas")
				foreach($value as $val)
					$this->db->addResourceSchema($groupID, $val);
					
			if(in_array($key,array('id', 'meta','schemas')))
				continue;

			if($key == "members")
				foreach($value as $member)
					$this->db->addGroupMember($groupID, $member['value']);
					
			$this->db->addResourceAttribute($groupID, $key, json_encode($value));
		}
		
		header("Content-Type: application/json", true, 201);
		echo $this->getGroup($groupID, 1);
	}
	
	
	public function getGroup($groupID, $isIncluded='')
	{
		if(!$this->db->groupExists($groupID, "2.0"))
			exit($this->throwError(404, "This group does not exist."));
		
		$attributes = $this->db->getResourceAttributes($groupID);
		$metadata = $this->db->getMetadata($groupID);
		$schemas = $this->db->getResourceSchemas($groupID);
		$members = $this->db->getGroupMembers($groupID);
		$etag = md5(json_encode($attributes) . json_encode($schemas) . json_encode($metadata) . json_encode($members));
		
		if($isIncluded == '')
		{
			header("Etag: " . $etag);
			header("Last-Modified: ".gmdate("D, d M Y H:i:s", $metadata['lastUpdated'])." GMT");
		}
		
		$payload = array();
		$payload['schemas'] = $schemas;
		$payload['id'] = $groupID;
		$payload['displayName'] = $attributes['displayName'];
		$payload['members'] = array();
		
		foreach($members as $member)
		{
			$userAttributes = $this->db->getResourceAttributes($member);
			$user = array('value' => $member, 'display' => $userAttributes['userName']);
			$payload['members'][] = $user;
		}
		
		if(count($schemas) > 1)
			foreach($schemas as $schema)
			{
				if($schema == "urn:ietf:params:scim:schemas:core:2.0:Group")
					continue;
				
				$payload[$schema] = $attributes[$schema];
			}
		
		$payload['meta'] = array(
			"resourceType" => "Group",
			"created" => gmdate("c", $metadata['created']),
			"lastModified" => gmdate("c", $metadata['lastUpdated']),
			"version" => $etag,
			"location" => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]" . str_replace("index.php", "", $_SERVER['SCRIPT_NAME']) . "scim/v2/Groups/" . $groupID
		);

		if($isIncluded == '')
			header("Content-Type: application/json", true, 200);
		
		if($isIncluded != '')
			return preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
		
		else
			echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
	}
	
	public function listGroups($options)
	{
		$payload = array();
		$groups = $this->db->listResources("2.0", 1, $options);
		$totalGroups = $this->db->listResources("2.0", 1, $options, true);
		
		$payload['schemas'] = array('urn:ietf:params:scim:api:messages:2.0:ListResponse');
		$payload['totalResults'] = $totalGroups;
		$payload['startIndex'] = 1;
		$payload['itemsPerPage'] = 0;
		
		if((int) $options['startIndex'] > 0)
			$payload['startIndex'] = (int) $options['startIndex'];
		
		if((int) $options['count'] > 0 && $options['count'] < $totalGroups)
			$payload['itemsPerPage'] = (int) $options['count'];
		elseif($totalGroups > 0)
			$payload['itemsPerPage'] = $totalGroups;
		
		$payload['Resources'] = array();

		foreach($groups as $group)
			$payload['Resources'][] = json_decode($this->getGroup($group, 1));
		
		header("Content-Type: application/json", true, 200);
		echo preg_replace('/[\x00-\x1F\x7F]/u', '', json_encode($payload, JSON_UNESCAPED_SLASHES));
	}
	
	public function patchGroup($requestBody, $groupID)
	{
		$requestBody = json_decode($requestBody, 1);
		$groupAttributes = $this->db->getResourceAttributes($groupID);
		
		foreach($requestBody as $key => $value)
		{
			if(in_array($key,array('schemas', 'id', 'groups')))
				continue;
			
			elseif($key == "Operations" && is_array($value))
				foreach($value as $val)
				{
					if($val['path'] == "members")
					{
						if($val['op'] == "replace")
						{
							$this->db->deleteAllGroupMembership($groupID);
							foreach($val['value'] as $members)
								$this->db->addGroupMember($groupID, $members['value']);
						}elseif($val['op'] == "add")
							foreach($val['value'] as $members)
								$this->db->addGroupMember($groupID, $members['value']);
						elseif($val['op'] == "remove")
							foreach($val['value'] as $members)
								$this->db->deleteGroupMembership($groupID, $members['value']);
					}else{
						if($val['op'] == "replace")
						{
							foreach($val['value'] as $a => $v)
							{							
								$schemas = $this->db->getResourceSchemas($groupID);
								
								$this->db->deleteResourceAttribute($groupID, $a);
								$this->db->addResourceAttribute($groupID, $a, json_encode($v));
								
								if($schemas[$a] != "")
									$this->db->addResourceSchema($groupID, $a);
							}
						}elseif($val['op'] == "add")
							foreach($val['value'] as $a => $v)
							{								
								$this->db->addResourceAttribute($groupID, $a, json_encode($v));
							}
						elseif($val['op'] == "remove")
						{
							if(substr($val['path'],0,7) == "members")
							{
								preg_match('/[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}/', $val['path'],$matches);
								$this->db->deleteGroupMembership($groupID, $matches[0]);
							}else{
								$a = "todo";
								$this->db->deleteResourceAttribute($groupID, $a);
							}
						}
					}
				}
		}
		$this->db->updateTimestamp($groupID);
		
		header("Content-Type: application/json", true, 200);
		$this->getGroup($groupID);
	}
	
	public function putGroup($requestBody, $groupID)
	{
		$this->parseGroupPayload($requestBody, true);
		$requestBody = json_decode($requestBody, 1);
		
		$this->db->deleteResourceSchemas($groupID);
		$this->db->deleteResourceAttributes($groupID);
		
		foreach($requestBody as $key => $value)
		{
			if($key == "schemas")
				foreach($value as $val)
					$this->db->addResourceSchema($groupID, $val);
					
			if(in_array($key,array('id', 'meta','schemas')))
				continue;

			if($key == "members")
				foreach($value as $member)
					$this->db->addGroupMember($groupID, $member['value']);
					
			$this->db->addResourceAttribute($groupID, $key, json_encode($value));
		}
		$this->db->updateTimestamp($groupID);
		
		header("Content-Type: application/json", true, 200);
		$this->getGroup($groupID);
	}
	
	public function deleteGroup($groupID)
	{
		if(!$this->db->groupExists($groupID, "2.0"))
			$this->throwError(404, "Group selected does not exist.");
		
		$this->db->deleteResourceSchemas($groupID);
		$this->db->deleteResourceAttributes($groupID);
		$this->db->deleteResource($groupID);
		$this->db->deleteAllGroupMembership($groupID);
		header("Content-Type: application/json", true, 204);	
	}
	
	private function parseGroupPayload($payload, $groupCheck=false)
	{
		$payload = json_decode($payload, 1);
		
		if(!$payload)
			exit($this->throwError(400, "Incorrect request was sent to the SCIM server."));
		
		if($groupCheck == false)
			if($this->db->groupExists($payload['displayName'], "2.0"))
				exit($this->throwError(409, "Group already exists in the database."));
			
		if($payload['schemas'] == "" || !in_array("urn:ietf:params:scim:schemas:core:2.0:Group", $payload['schemas']))
			exit($this->throwError(400, "Incorrect schema was provided in the request."));
		
		if($payload['displayName'] == "")
			exit($this->throwError(400, "No displayName was provided in the request."));
	}
	
	public function showServiceProviderConfig()
	{		
		$payload = array();
		
		$payload['schemas'] = array("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig");
		$payload['patch'] = array("supported" => true);
		$payload['bulk'] = array("supported" => false, "maxOperations" => 0, "maxPayloadSize" => 0);
		$payload['filter'] = array("supported" => false, "maxResults" => 0);
		$payload['changePassword'] = array("supported" => true);
		$payload['sort'] = array("supported" => false);
		$payload['etag'] = array("supported" => true);
		$payload['authenticationSchemes'] = array(
			array("name" => "OAuth Bearer Token", "description" => "Authentication Scheme using the OAuth Bearer Token Standard", "type" => "oauthbearertoken"),
			array("name" => "HTTP Basic", "description" => "Authentication Scheme using the Http Basic Standard", "type" => "httpbasic")
		);
		
		echo json_encode($payload);
	}
	
	public function throwError($statusCode, $description)
	{
		header("Content-Type: application/json", true, $statusCode);
		
		exit(
			json_encode(
				array(
					'schemas' => array("urn:ietf:params:scim:api:messages:2.0:Error"),
					'detail' => $description,
					'status' => $statusCode
				)
			)
		);
	}
}
