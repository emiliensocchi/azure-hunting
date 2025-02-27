#### Description #################################################################################
#
# Indexes all reply URLs containing 'azurewebsites.net' for all the App registrations in a tenant.
#
# Requirements:
#    An access token with the following MS Graph permissions (as application or delegated permissions):
#       - Application.Read.All
####

# Pass-the-token authentication
$msgraphToken  = '_VALID-ACCESS-TOKEN-FOR_MS-GRAPH_'
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force 
Connect-MgGraph -NoWelcome -AccessToken $secureToken -ErrorAction Stop 

# Retrieve tenant Id
$tenantId = (Get-MgOrganization).Id

# Set output file location
$path = "C:\Users\$env:UserName\Downloads\"
$file = "_dangling-redirectURIs.txt" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"

# Get all applications
$apps = Get-MgApplication -All

# Filter applications with reply URLs containing "azurewebsites.net"
$urls = $apps | Where-Object { $_.Web.RedirectUris -match "azurewebsites.net" } | Select-Object -ExpandProperty Web | Select-Object -ExpandProperty RedirectUris | Where-Object { $_ -match "azurewebsites.net" }

$domains = @()
foreach ($domain in $urls) {
    if ($domain -match "http://") {
        $domains += ($domain -split "http://" -split "/")[1]
    }
    if ($domain -match "https://") {
        $domains += ($domain -split "https://" -split "/")[1]
    }
}

Write-Output $domains
Write-Output ""
Write-Output ""

Set-Content -Path $resultFile -Value $domains
Write-Output "Results successfully exported to: $resultFile"
