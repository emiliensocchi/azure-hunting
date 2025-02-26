# Find Multi-tenant Apps with unlocked App instance properties

Tool to find multi-tenant applications with unlocked app instance properties ([more info](https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-app-instance-property-locks)).


## Requirements

- Powershell 7+
- [Microsoft Graph PowerShell](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0)
- An access token with the following MS Graph permissions (as application or delegated permissions):
  - Application.ReadWrite.All
  - Directory.Read.All


## Disclaimer

For some unknow reason, removing the certificate uploaded to test the 'keyCredentials' property sometimes fails. If keeping a clean tenant is absolutely necessary, an alternative is to test **only** the 'passwordCredentials' property and assume that that the results are similar for the 'keyCredentials' property.

Note that the uploaded certificate is set to expire after 1 minute.


## Instructions

### 1. Install and Import the Microsoft Graph PowerShell module
```shell
Install-Module Microsoft.Graph -Scope CurrentUser -Repository PSGallery -Force
```

### 2. Set the value of the following variables in the script

```shell
$servicePrincipalId = '_OBJECT-ID-OF-YOUR_MULTI_TENANT-SP_'
```

```shell
$msgraphToken = '_VALID-ACCESS-TOKEN-FOR_MS-GRAPH_'
```

### 3. Fetch unlocked multi-tenant apps
```shell
.\Find-UnlockedMultiTenantApps.ps1
```
