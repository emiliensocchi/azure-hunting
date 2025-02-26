#### Description ##############################################################################################################################
#
# Indexes all applications enabled for SSO via Entra ID, and displays whether they require app role assignments.
#
# Requirements:
#    An access token with the following MS Graph permissions (as application or delegated permissions):
#       - Application.Read.All 
#
#####

# Pass-the-token authentication
$msgraphToken  = '_VALID-ACCESS-TOKEN-FOR_MS-GRAPH_'
$secureToken = ConvertTo-SecureString -String $msgraphToken -AsPlainText -Force 
Connect-MgGraph -NoWelcome -AccessToken $secureToken -ErrorAction Stop 

# Retrieve tenant Id
$tenantId = (Get-MgOrganization).Id

# Set output file location
$path = "C:\Users\$env:UserName\Downloads\"
$file = "_sso-enabled-apps.csv" 
$date = (Get-Date -UFormat "%Y-%m-%d")
$resultFile = "${path}${date}${file}"

# Get Service Principals that are configured with SSO
$servicePrincipals = Get-MgServicePrincipal -All

$ssoEnabledApps = $servicePrincipals | Where-Object {
    -not ([string]::IsNullOrEmpty($_.PreferredSingleSignOnMode))
}

# Export results
$ssoEnabledApps | Select-Object DisplayName, AppId, PreferredSingleSignOnMode, AppRoleAssignmentRequired, @{Name="MyAppsUri (SSO)";Expression={"https://launcher.myapps.microsoft.com/api/signin/$($_.AppId)?tenantId=$tenantId"}} |
Export-Csv -Path $resultFile -NoTypeInformation

Write-Host "Results exported to: $resultFile"
