# ROADrecon

Collection of SQL queries to retrieve information manually from the `roadrecon` database.


## Quick wins

### List all users reported as 'compromised' by AAD Identity Protection

```shell
SELECT objectId, displayName, isCompromised FROM Users
WHERE isCompromised IS NOT NULL
```

### List all app registrations with a plain-text secret (should never be possible!)

```shell
SELECT appId, displayName, passwordCredentials FROM Applications
WHERE passwordCredentials NOT LIKE '%"value": null%'
AND passwordCredentials != "[]"
```


## User investigation

### List all users that are not assigned any group
```shell
SELECT objectId, displayName FROM Users 
WHERE objectId NOT IN (SELECT User FROM lnk_group_member_user)
```


## Entra ID role investigation

### List all custom Entra ID roles (i.e. not built in) 

```shell
SELECT * FROM RoleDefinitions
WHERE isBuiltIn == "0"
```


## Dynamic group investigation

### List all dynamic groups with their membership rules, excluding those with the extensionAttributes property (on-prem attribute, so not vulnerable to common dynamic-rule issues)

```shell
SELECT description, displayName, membershipRule  FROM Groups
WHERE groupTypes LIKE '%DynamicMembership%'
AND membershipRule NOT LIKE '%extensionAttribute%'
```


## App Registration investigation

### Get all reply URLs for all app registrations 

Analyze them through Aquatone and see if some refer to interesting websites

```shell
SELECT DISTINCT replyUrls FROM Applications
WHERE replyUrls != "[]"
AND replyUrls != '["http://localhost"]'
AND replyUrls != '["https://localhost"]'
AND replyUrls != '["https://VisualStudio/SPN"]'
```

### List all app registrations with an associated Managed Identity

```shell
SELECT appId, displayName, encryptedMsiApplicationSecret FROM Applications
WHERE encryptedMsiApplicationSecret != ""
```

### List all app registrations that are multitenant

Note: users from other directories still need to be brought to the tenant as B2B guest users to be authorized to access the app

```shell
SELECT appId, displayName, availableToOtherTenants, replyUrls FROM Applications
WHERE availableToOtherTenants == "1"
```

### List all app registrations that have their token configured with optional claims 

```shell
SELECT appId, displayName, optionalClaims FROM Applications
WHERE optionalClaims != ""
```

### List all application owners

```shell
SELECT DISTINCT objectId, displayName, signInNames FROM Users
INNER JOIN lnk_application_owner_user ON lnk_application_owner_user.User = Users.objectId
```

### List all app registrations with static application permissions
```shell
SELECT appId, displayName, requiredResourceAccess FROM Applications
WHERE requiredResourceAccess != "[]"
```
