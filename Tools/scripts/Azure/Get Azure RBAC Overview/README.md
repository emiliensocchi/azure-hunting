# Get Azure RBAC Overview

Tool to get an overview of all Azure RBAC permissions assigned to the following security principals in all subscriptions of an environment:
- Users
- Groups
- Service principals and Managed Identities (both user-assigned and system-assigned)

Note: Under 'Scope', '/' means that the scope for the role assignement is the Root management group


## Requirements

- Powershell 7+
- [Az PowerShell](https://learn.microsoft.com/en-us/powershell/azure/install-azps-windows?view=azps-11.2.0&tabs=powershell&pivots=windows-psgallery)
- Read access to all subscriptions of an environment


## Instructions

### 1.  Install and Import the Az PowerShell module
```shell
Install-Module -Name Az -Repository PSGallery -Force
```


### 2. Run the tool
```shell
.\Get-IAMOverview.ps1
```
