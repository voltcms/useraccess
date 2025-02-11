# VoltCMS UserAccess

PHP User and Access Management

SCIM

8.1.  Minimal User Representation

   The following is a non-normative example of the minimal required SCIM
   representation in JSON format.

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "userName": "bjensen@example.com",
  "meta": {
    "resourceType": "User",
    "created": "2010-01-23T04:56:22Z",
    "lastModified": "2011-05-13T04:42:34Z",
    "version": "W\/\"3694e05e9dff590\"",
    "location":
     "https://example.com/Users/2819c223-7f76-453a-919d-413861904646"
  }
}



8.4.  Group Representation

   The following is a non-normative example of the SCIM Group
   representation in JSON format.

   {
     "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
     "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
     "displayName": "Tour Guides",
     "members": [
       {
         "value": "2819c223-7f76-453a-919d-413861904646",
         "$ref":
   "https://example.com/Users/2819c223-7f76-453a-919d-413861904646",
         "display": "Babs Jensen"
       },
       {
         "value": "902c246b-6245-4190-8e05-00816be7344a",
         "$ref":
   "https://example.com/Users/902c246b-6245-4190-8e05-00816be7344a",
         "display": "Mandy Pepperidge"
       }
     ],
     "meta": {
       "resourceType": "Group",
       "created": "2010-01-23T04:56:22Z",
       "lastModified": "2011-05-13T04:42:34Z",
       "version": "W\/\"3694e05e9dff592\"",
       "location":
   "https://example.com/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a"
     }
   }
