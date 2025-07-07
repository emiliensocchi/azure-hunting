# Find Dangling DNS resources

Tool to find dangling DNS records from multiple Azure subscriptions.


## Requirements

- Powershell 7+
- [Azure AD PowerShell](https://learn.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0)
- Read access on the subscription(s) in scope


## Instructions

### 1. Install and Import the Az PowerShell module
```shell
Install-Module -Name Az -Repository PSGallery -Force
```

### 2. Install and Import the AzDanglingDomain PowerShell module 
```shell
Install-Module -Name AzDanglingDomain -Repository PSGallery -Force
```

### 3. Authenticate to the Azure control plane
```shell
Connect-AzAccount
```
```shell
$armToken = '' 
Connect-AzAccount -AccessToken $armToken -AccountId current
```


### 4. Fetch DNS records from all subscriptions
```shell
Get-DanglingDnsRecords -FetchDnsRecordsFromAzureSubscription
```


## Prevention

https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover


## Credits

https://github.com/Azure/Azure-Network-Security/tree/master/Cross%20Product/DNS%20-%20Find%20Dangling%20DNS%20Records
