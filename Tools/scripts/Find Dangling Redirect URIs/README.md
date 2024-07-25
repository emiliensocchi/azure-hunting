# Find Dangling Redirect URIs

Tool to find dangling redirect URIs in App Registrations.


## Requirements

- Powershell 7+
- [Azure AD PowerShell](https://learn.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
- Read access to the tenant's App Registrations


## Instructions

### 1. Install and Import the Azure AD PowerShell module
```shell
Install-Module -Name AzureAD -Repository PSGallery -Force
```

### 2. Fetch App Registrations from the tenant
```shell
.\Find-DanglingRedirectURIs.ps1
```

## Credits

https://securecloud.blog/2021/05/28/using-powershell-to-find-dangling-redirect-uris-in-azure-ad-tenant/
