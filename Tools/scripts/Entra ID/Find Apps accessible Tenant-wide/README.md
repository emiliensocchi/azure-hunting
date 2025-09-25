# Find all SSO-enabled applications

Tool to find all applications enabled for Single Sign-On (SSO) via Entra ID, and identify those that do not require app role assignments (i.e. those are available tenant wide).

## Requirements

- Powershell 7+
- [Microsoft Graph PowerShell Beta](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-beta)
- An access token with the following MS Graph permissions (as application or delegated permissions):
  - Application.Read.All


## Instructions

### 1. Install and Import the Microsoft Graph Beta PowerShell module
```shell
Install-Module Microsoft.Graph.Beta -Scope CurrentUser -Repository PSGallery -Force
```

### 2. Set the value of the following variables in the script

```shell
$msgraphToken = '_VALID-ACCESS-TOKEN-FOR_MS-GRAPH_'
```

### 3. Fetch SSO-enabled applications from the tenant
```shell
.\Find-AllSsoEnabledApps.ps1
```
